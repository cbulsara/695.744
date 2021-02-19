[BITS 32]

;;;;;;;;;;
;; ADD
;;;;;;;;;;
db  0x05
db  0x44
db  0x43
db  0x42
db  0x41
add ecx, 0x11223344
add dword [ecx], 0x11223344
add dword [byte ecx + 4], 0x11223344
add dword [dword ecx + 4], 0x11223344
add dword [0x44556677], 0x11223344
add ecx, esi
add dword [ecx], esi
add dword [byte ecx + 4], esi
add dword [dword ecx + 4], esi
add esi, dword [ecx]
add esi, dword [byte ecx + 4]
add esi, dword [dword ecx + 4]
add esi, dword [0x44556677]

label_and:
;;;;;;;;;;
;; AND
;;;;;;;;;;
db  0x25
db  0x44
db  0x43
db  0x42
db  0x41
and ecx, 0x11223344
and dword [ecx], 0x11223344
and dword [byte ecx + 4], 0x11223344
and dword [dword ecx + 4], 0x11223344
and dword [0x44556677], 0x11223344
and ecx, esi
and dword [ecx], esi
and dword [byte ecx + 4], esi
and dword [dword ecx + 4], esi
and esi, dword [ecx]
and esi, dword [byte ecx + 4]
and esi, dword [dword ecx + 4]
and esi, dword [0x44556677]

;;;;;;;;;;;;
;; CALL
;;;;;;;;;;;;
call label_and ; call back
call label_cmp ; call forward
call eax
call dword [eax]
call dword [byte eax + 4]
call dword [dword eax + 4]
call dword [0x44556677]

;;;;;;;;;;;;
;; CMP
;;;;;;;;;;;;
label_cmp:
db  0x3d
db  0x44
db  0x43
db  0x42
db  0x41
cmp ecx, 0x11223344
cmp dword [ecx], 0x11223344
cmp dword [byte ecx + 4], 0x11223344
cmp dword [dword ecx + 4], 0x11223344
cmp dword [0x44556677], 0x11223344
cmp ecx, esi
cmp dword [ecx], esi
cmp dword [byte ecx + 4], esi
cmp dword [dword ecx + 4], esi
cmp esi, dword [ecx]
cmp esi, dword [byte ecx + 4]
cmp esi, dword [dword ecx + 4]
cmp esi, dword [0x44556677]

;;;;;;;;;;;;
;; DEC
;;;;;;;;;;;;
db 0xFF
db 0xCF ; dec edi
dec ecx
dec dword [ecx]
dec dword [byte ecx + 4]
dec dword [dword ecx + 4]
dec dword [0x44556677]

;;;;;;;;;;;;
;; IDIV
;;;;;;;;;;;;
idiv ecx
idiv dword [ecx]
idiv dword [byte ecx + 4]
idiv dword [dword ecx + 4]
idiv dword [0x44556677]

;;;;;;;;;;;;
;; IMUL
;;;;;;;;;;;;
imul ecx
imul dword [ecx]
imul dword [byte ecx + 4]
imul dword [dword ecx + 4]
imul esi, dword [ecx]
imul esi, dword [byte ecx + 4]
imul esi, dword [dword ecx + 4]
imul esi, dword [0x44556677]
imul esi, dword [ecx], 0x11223344
imul esi, dword [byte ecx + 4], 0x11223344
imul esi, dword [dword ecx + 4], 0x11223344
imul esi, dword [0x44556677], 0x11223344

;;;;;;;;;;;;
;; INC
;;;;;;;;;;;;
label_inc:
db 0xFF
db 0xC7 ; inc edi
inc ecx
inc dword [ecx]
inc dword [byte ecx + 4]
inc dword [dword ecx + 4]
inc dword [0x44556677]

;;;;;;;;;;;;
;; JMP
;;;;;;;;;;;;
label_jmp:
jmp near label_and ; jmp back
jmp near label_lea ; jmp forward
jmp short label_inc ; jmp back rel8
jmp short label_jz ; jmp forward rel8
jmp ecx
jmp dword [ecx]
jmp dword [byte ecx + 4]
jmp dword [dword ecx + 4]
jmp dword [0x44556677]

;;;;;;;;;;;;
;; jCC
;;;;;;;;;;;;
label_jz:
jz near label_and ; jz back
jz near label_lea ; jz forward
jz short label_jmp ; jz back rel8
jz short label_jz ; jz forward rel8

jnz near label_and ; jnz back
jnz near label_lea ; jnz forward
jnz short label_jmp ; jnz back rel8
jnz short label_jz ; jnz forward rel8

;;;;;;;;;;;;
;; LEA
;;;;;;;;;;;;
label_lea:
lea esi, [ ecx ]
lea esi, [ byte ecx + 4 ]
lea esi, [ dword ecx + 4 ]
lea esi, [ 0x44556677 ]

;;;;;;;;;;
;; MOV
;;;;;;;;;;
mov ecx, 0x11223344
mov dword [ecx], 0x11223344
mov dword [byte ecx + 4], 0x11223344
mov dword [dword ecx + 4], 0x11223344
mov dword [0x44556677], 0x11223344
mov ecx, esi
mov dword [ecx], esi
mov dword [byte ecx + 4], esi
mov dword [dword ecx + 4], esi
mov esi, dword [ecx]
mov esi, dword [byte ecx + 4]
mov esi, dword [dword ecx + 4]
mov esi, dword [0x44556677]

;;;;;;;;;;;
;; MOVSD
;;;;;;;;;;;
movsd


;;;;;;;;;;;;
;; NEG
;;;;;;;;;;;;
neg ecx
neg dword [ecx]
neg dword [byte ecx + 4]
neg dword [dword ecx + 4]
neg dword [0x44556677]

;;;;;;;;;;;;
;; NOP
;;;;;;;;;;;;
nop

;;;;;;;;;;;;
;; NOT
;;;;;;;;;;;;
not ecx
not dword [ecx]
not dword [byte ecx + 4]
not dword [dword ecx + 4]
not dword [0x44556677]

;;;;;;;;;;;;
;; MUL
;;;;;;;;;;;;
mul ecx
mul dword [ecx]
mul dword [byte ecx + 4]
mul dword [dword ecx + 4]
mul dword [0x44556677]

;;;;;;;;;;
;; OR
;;;;;;;;;;
db  0x0D
db  0x44
db  0x43
db  0x42
db  0x41
or ecx, 0x11223344
or dword [ecx], 0x11223344
or dword [byte ecx + 4], 0x11223344
or dword [dword ecx + 4], 0x11223344
or dword [0x44556677], 0x11223344
or ecx, esi
or dword [ecx], esi
or dword [byte ecx + 4], esi
or dword [dword ecx + 4], esi
or esi, dword [ecx]
or esi, dword [byte ecx + 4]
or esi, dword [dword ecx + 4]
or esi, dword [0x44556677]

;;;;;;;;;;;;;;
;; POP
;;;;;;;;;;;;;;
db 0x8F
db 0xC7
pop ecx
pop dword [ ecx ]
pop dword [ byte ecx + 4 ]
pop dword [ dword ecx + 4 ]
pop dword [ 0x44556677 ]

;;;;;;;;;;;;;;
;; PUSH
;;;;;;;;;;;;;;
db 0xFF
db 0xF7 
push ecx
push dword [ ecx ]
push dword [ byte ecx + 4 ]
push dword [ dword ecx + 4 ]
push dword [ 0x44556677 ]
push 0x44556677

;;;;;;;;;;;;;;;;
;; REPNE CMPSD
;;;;;;;;;;;;;;;
repne cmpsd

;;;;;;;;;;;;;;
;; RET
;;;;;;;;;;;;;;
retf
retf 0x4455
retn
retn 0x4455

;;;;;;;;;;;;;
;; SHIFTS
;;;;;;;;;;;;;
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

;;;;;;;;;;
;; SBB
;;;;;;;;;;
sbb ecx, 0x11223344
sbb dword [ecx], 0x11223344
sbb dword [byte ecx + 4], 0x11223344
sbb dword [dword ecx + 4], 0x11223344
sbb dword [0x44556677], 0x11223344
sbb ecx, esi
sbb dword [ecx], esi
sbb dword [byte ecx + 4], esi
sbb dword [dword ecx + 4], esi
sbb esi, dword [ecx]
sbb esi, dword [byte ecx + 4]
sbb esi, dword [dword ecx + 4]
sbb esi, dword [0x44556677]

;;;;;;;;;;
;; TEST
;;;;;;;;;;
db  0xA9
db  0x44
db  0x43
db  0x42
db  0x41
test ecx, 0x11223344
test dword [ecx], 0x11223344
test dword [byte ecx + 4], 0x11223344
test dword [dword ecx + 4], 0x11223344
test dword [0x44556677], 0x11223344
test ecx, esi
test dword [ecx], esi
test dword [byte ecx + 4], esi
test dword [dword ecx + 4], esi
test esi, dword [ecx]
test esi, dword [byte ecx + 4]
test esi, dword [dword ecx + 4]
test esi, dword [0x44556677]


;;;;;;;;;;
;; XOR
;;;;;;;;;;
db  0x35
db  0x44
db  0x43
db  0x42
db  0x41
xor ecx, 0x11223344
xor dword [ecx], 0x11223344
xor dword [byte ecx + 4], 0x11223344
xor dword [dword ecx + 4], 0x11223344
xor dword [0x44556677], 0x11223344
xor ecx, esi
xor dword [ecx], esi
xor dword [byte ecx + 4], esi
xor dword [dword ecx + 4], esi
xor esi, dword [ecx]
xor esi, dword [byte ecx + 4]
xor esi, dword [dword ecx + 4]
xor esi, dword [0x44556677]
