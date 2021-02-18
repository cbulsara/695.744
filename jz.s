[BITS 32]
label_and:
jz near label_and ; jz back
jz near label_lea ; jz forward
label_jz:
jz short label_jmp ; jz back rel8
jz short label_jz ; jz forward rel8
label_lea:
jnz near label_and ; jnz back
jnz near label_lea ; jnz forward
label_jmp:
jnz short label_jmp ; jnz back rel8
jnz short label_jz ; jnz forward rel8
