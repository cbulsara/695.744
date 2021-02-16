import argparse
import binascii
import logging
import sys

logging.basicConfig()
log = logging.getLogger('disasm')
log.setLevel(logging.ERROR)     # enable CRITICAL and ERROR messages by default

opcodeLookup = {
    b'05': ['add', 'add eax, imm32', 'add eax,', 5],
    b'81': ['add', 'add r/m32, imm32', 'add ', 6],
    b'01': ['add', 'add r/m32, r32', 'add ', 2],
    b'03': ['add', 'add r32, r/m32', 'add ', 2],
    b'd0': ['fake_mov', 'fake_mov', 'fake mov', 2],
    b'25': ['and', 'and eax, imm32', 'and eax, ', 5],
    b'81': ['and', 'and r/m32, imm32', 'and ', 6],     
    b'21': ['and', 'and r/m32, r32', 'and ', 2],
    b'23': ['and', 'and r32, r/m32', 'and ', 2],
    b'e8': ['call', 'call rel 32', 'call ', 5],
    b'ff': ['call', 'call r/m32', 'call ', 2],              #TODO: handle ambiguous
    b'0f': ['clflush', 'clflush m8', 'clflush 0xAE', 2],
    b'ff': ['dec', 'dec r/m32'],                         #TODO: handle ambiguous
    b'48': ['dec', 'dec r32', '000'],
    b'49': ['dec', 'dec r32', '001'],
    b'4a': ['dec', 'dec r32', '010'],
    b'4b': ['dec', 'dec r32', '011'],
    b'4c': ['dec', 'dec r32', '100'],
    b'4d': ['dec', 'dec r32', '101'],
    b'4e': ['dec', 'dec r32', '110'],
    b'4f': ['dec', 'dec r32', '111'],
    b'f7': ['idiv', 'idiv r/m32'],                         #TODO:handle ambiguous
    b'f7': ['imul', 'imul r/m32'],                           #TODO handle ambiguous
    b'0f': ['imul', 'imul r32, r/m32'],                         #TODO: handle ambiguous
    b'69': ['imul', 'imul r32, r/m32, imm32'],                    
    b'ff': ['inc', 'inc r/m32'],                          #TODO: handle ambiguous    
    b'40': ['inc', 'inc r32', '000'],
    b'41': ['inc', 'inc r32', '001'],
    b'42': ['inc', 'inc r32', '010'],
    b'43': ['inc', 'inc r32', '011'],
    b'44': ['inc', 'inc r32', '100'],
    b'45': ['inc', 'inc r32', '101'],
    b'46': ['inc', 'inc r32', '110'],
    b'47': ['inc', 'inc r32', '111']
}

x86RegLookup = {
	'000':'eax',
	'001':'ecx',
	'010':'edx',
	'011':'ebx',
	'100':'esp',
	'101':'ebp',
	'110':'esi',
	'111':'edi'
}

def dec2bin(x):
	return "".join(map(lambda y:str((x>>y)&1), range(8-1, -1, -1)))

def flipDword(x):
    if len(x) != 8:
        log.error("flipDword: Tried to flip a DWORD that wasn't a DWORD")
    flipped = b''.join((x[6:],x[4:6],x[2:4],x[0:2]))
    log.info(flipped)
    return flipped

def format_line(hexbytes, text):
    hexstr = ''.join(['{:02x}'.format(x) for x in hexbytes])
    return '{:<24}{}'.format(hexstr, text)


def format_unknown(hexbyte):
    return format_line([hexbyte], 'db 0x{:02x}'.format(hexbyte))


def format_label(address):
    return 'offset_{:08x}h:\n'.format(address)


def format_instr(hexbytes, mnemonic, op1=None, op2=None, op3=None):
    log.info(op1)
    log.info(op2)
    line = format_line(hexbytes, mnemonic)
    if op1:
        line = '{} {}'.format(line, op1)
        if op2:
            line = '{}, {}'.format(line, op2)
            if op3:
                line = '{}, {}'.format(line, op3)
    log.info(line)
    return line

def parse_int3(instr):
    if 1 == len(instr) and b'\xcc' == instr:
        log.info('Found int3!')
        return format_line(instr, 'int3')
    return None


def parse_cpuid(instr):
    if 2 == len(instr) and b'\x0f\x31' == instr:
        log.info('Found cpuid!')
        return format_line(instr, 'cpuid')
    return None


# This is not really "mov eax, eax", only an example of a formatted instruction
def parse_fake_mov(instr, inbytes, currentOffset):
    if 2 == len(instr) and b'\xd0\x0d' == instr:
        log.info('Found fake mov!')
        return format_instr(instr, 'mov', 'eax', 'eax')

def parse_modrm(modrmByte):
    modrmBinary = bin(int(modrmByte, 16))[2:].zfill(8)
    log.info("MODRM Binary: " + str(modrmBinary))
    mod = modrmBinary[0:2]
    reg = modrmBinary[2:5]
    rm = modrmBinary[5:8]

    return mod, reg, rm

#add    TODO make [byte] [dword] like call 
def parse_add(instr, inbytes, currentOffset):
    
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
    
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)
    
    
    #05  
    if opcodeString == b'05':
        #add remaining bytes to instruction
        for x in range(currentOffset + 1, currentOffset + opcodeLookup[opcodeString][3]):
            instr.append(inbytes[x])
        
        log.info("parse_add::Found 0x05")
        byteString = binascii.hexlify(instr)
        log.info(byteString)
        mnemonic = opcodeLookup[opcodeString][0]
        operand1 = 'eax'
        log.info(byteString[-8:])
        operand2 = flipDword(byteString[-8:])
        log.info(operand2)
        offsetIncrement = opcodeLookup[opcodeString][3]
        return offsetIncrement, format_instr(instr, mnemonic, operand1, "0x" + operand2.decode("utf-8"))
    #/05

    #81
    elif opcodeString == b'81':
        log.info("parse_add:Found 0x81")
        instructionSize = opcodeLookup[opcodeString][3]
        


        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))
        
        #if reg = 4, this is AND 81 /4
        if reg == '100':
            return parse_and(origInstruction, inbytes, currentOffset)
        
        #[r/m]
        if mod == '00':
            log.info("[r/m]")
            log.info(opcodeString)
            
            #[disp 32]
            if rm == '101':
                log.info("[disp 32]")
                
                #instruction size = 10 (opcode + modrm + dword + dword)
                instructionSize = 10
                
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "add dword"
                operand1 = "[0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
                operand2 = "0x" + flipDword(byteString[12:]).decode("utf-8")
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            #[not special case]
            else:
                #read in remaining bytes, instruction size is the default 6 (opcode + modrm + imm32)
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])

                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "add dword"
                operand1 = "[" + x86RegLookup[rm] + "]"
                operand2 = "0x" + flipDword(byteString[4:]).decode("utf-8")
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
        
        elif mod == '01':
            log.info("[r/m + byte]")

            #instruction size = 7 (opcode + modrm + byte + imm32)
            instructionSize = 7

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "add dword"
            operand1 = "[" + x86RegLookup[rm] + " + " + byteString[4:6].decode("utf-8") +"]"
            operand2 = "0x" + flipDword(byteString[6:]).decode("utf-8")
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
        elif mod == '10':
            log.info("[r/m + dword]")

            #instruction size = 7 (opcode + modrm + dword + imm32)
            instructionSize = 10

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "add dword"
            operand1 = "[" + x86RegLookup[rm] + " + 0x" + byteString[4:12].decode("utf-8") +"]"
            operand2 = "0x" + flipDword(byteString[12:]).decode("utf-8")
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
        elif mod == '11':
            log.info("r/m")

            #instruction size = 6 (opcode + modrm + imm32)
            instructionSize = 6

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "add"
            operand1 = x86RegLookup[rm]
            operand2 = "0x" + flipDword(byteString[4:]).decode("utf-8")
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)

        #base case: return db
        mnemonic = 'db 0x' + opcodeString.decode("utf-8")
        return 1, format_instr(instr, mnemonic)
    #/81

    #03 or 01
    elif opcodeString == b'03' or opcodeString == b'01':
        log.info("parse_add:Found 0x01 or 0x03")
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))

        if mod == '00':
            
            if rm == '101':
                log.info("parse_add:[disp32]")

                #instruction size is 6 (opcode + modrm + dword)
                instructionSize = 6
            
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = opcodeLookup[opcodeString][0] 
                operand1 = "0x" + flipDword(byteString[4:]).decode("utf-8")
                operand2 = x86RegLookup[reg]

                if opcodeString == b'01':
                    return instructionSize, format_instr(instr, mnemonic, operand1, "[" + operand2 + "]")
                else:
                    return instructionSize, format_instr(instr, mnemonic, operand2, "dword [" + operand1 + "]")
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            else:
                #instruction size is 2 (opcode + modrm)
                instructionSize = 2

                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = opcodeLookup[opcodeString][0]
                operand1 = x86RegLookup[reg]
                operand2 = x86RegLookup[rm]
            
            if opcodeString == b'03':
                return instructionSize, format_instr(instr, mnemonic, operand1, "[" + operand2 + "]")
            else:
                return instructionSize, format_instr(instr, mnemonic, "[" + operand2 +"]", operand1)
        
        if mod == '01':
            log.info("[r/m + byte]")
            
            #instruction size is 3 (opcode + modrm + byte)
            instructionSize = 3
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = opcodeLookup[opcodeString][0]
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm] + " + " + byteString[4:].decode("utf-8")
            
            if opcodeString == b'03':
                return instructionSize, format_instr(instr, mnemonic, operand1, "[" + operand2 + "]")
            else:
                return instructionSize, format_instr(instr, mnemonic, "[" + operand2 +"]", operand1)
        
        if mod == '10':
            log.info("r/m + dword")

            #instruction size is 6 (opcode + modrm + dword)
            instructionSize = 6
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = opcodeLookup[opcodeString][0]
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm] + " + 0x" + flipDword(byteString[4:]).decode("utf-8")

            if opcodeString == b'03':
                return instructionSize, format_instr(instr, mnemonic, operand1, "dword [" + operand2 + "]")
            else:
                return instructionSize, format_instr(instr, mnemonic, "dword [" + operand2 +"]", operand1)
        
        if mod == '11':
            log.info("r/m")

            #instruction size is 2 (opcode + modrm)
            instructionSize = 2

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = opcodeLookup[opcodeString][0]
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm]

            if opcodeString == b'03':
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
            else:
                return instructionSize, format_instr(instr, mnemonic, operand2, operand1)
                
        #base case: return db
        mnemonic = 'db 0x' + opcodeString.decode("utf-8")
        return 1, format_instr(instr, mnemonic)
    #03 or 01

    """POC
        byteString = binascii.hexlify(instr)
        log.info("Full instruction bytes:" + str(byteString))
        byteBinary = bin(int(byteString, 16))[2:]
        log.info(opcodeLookup[opcodeString])
        #log.info(byteString[0:2])
        log.info("Instruction Binary: " + str(byteBinary))
        #log.info("mod = " + str(byteBinary[0:2]))
        mod, reg, rm = parse_modrm(byteString[2:4])
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))"""

    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/add

#and    TODO make [byte] [dword] like call  
def parse_and(instr, inbytes, currentOffset):
    
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
   
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)
    #add eax, imm32  
    if opcodeString == b'25':
        #add remaining bytes to instruction
        for x in range(currentOffset + 1, currentOffset + opcodeLookup[opcodeString][3]):
            instr.append(inbytes[x])
        
        log.info("parse_add::Found 0x25")
        byteString = binascii.hexlify(instr)
        log.info(byteString)
        mnemonic = opcodeLookup[opcodeString][0]
        operand1 = 'eax'
        log.info(byteString[-8:])
        operand2 = flipDword(byteString[-8:])
        log.info(operand2)
        offsetIncrement = opcodeLookup[opcodeString][3]
        return offsetIncrement, format_instr(instr, mnemonic, operand1, "0x" + operand2.decode("utf-8"))

    elif opcodeString == b'81':
        log.info("parse_add:Found 0x81")
        instructionSize = opcodeLookup[opcodeString][3]
        
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))
                
        #if reg is 000 this is ADD 0x81 /0
        if reg == '000':
            return parse_add(origInstruction, inbytes, currentOffset)
        
        #[r/m]
        if mod == '00':
            log.info("[r/m]")
            log.info(opcodeString)
            
            #[disp 32]
            if rm == '101':
                log.info("[disp 32]")
                
                #instruction size = 10 (opcode + modrm + dword + dword)
                instructionSize = 10
                
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "and dword"
                operand1 = "[0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
                operand2 = "0x" + flipDword(byteString[12:]).decode("utf-8")
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            #[not special case]
            else:
                #read in remaining bytes, instruction size is the default 6 (opcode + modrm + imm32)
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])

                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "and dword"
                operand1 = "[" + x86RegLookup[rm] + "]"
                operand2 = "0x" + flipDword(byteString[4:]).decode("utf-8")
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
        
        elif mod == '01':
            log.info("[r/m + byte]")

            #instruction size = 7 (opcode + modrm + byte + imm32)
            instructionSize = 7

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "and dword"
            operand1 = "[" + x86RegLookup[rm] + " + " + byteString[4:6].decode("utf-8") +"]"
            operand2 = "0x" + flipDword(byteString[6:]).decode("utf-8")
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
        elif mod == '10':
            log.info("[r/m + dword]")

            #instruction size = 7 (opcode + modrm + dword + imm32)
            instructionSize = 10

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "and dword"
            operand1 = "[" + x86RegLookup[rm] + " + 0x" + byteString[4:12].decode("utf-8") +"]"
            operand2 = "0x" + flipDword(byteString[12:]).decode("utf-8")
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
        elif mod == '11':
            log.info("r/m")

            #instruction size = 6 (opcode + modrm + imm32)
            instructionSize = 6

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "and"
            operand1 = x86RegLookup[rm]
            operand2 = "0x" + flipDword(byteString[4:]).decode("utf-8")
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)

        #base case: return db
        mnemonic = 'db 0x' + opcodeString.decode("utf-8")
        return 1, format_instr(instr, mnemonic)

    elif opcodeString == b'23' or opcodeString == b'21':
        log.info("parse_add:Found 0x01 or 0x03")
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))

        if mod == '00':
            
            if rm == '101':
                log.info("parse_add:[disp32]")

                #instruction size is 6 (opcode + modrm + dword)
                instructionSize = 6
            
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = opcodeLookup[opcodeString][0] 
                operand1 = "0x" + flipDword(byteString[4:]).decode("utf-8")
                operand2 = x86RegLookup[reg]

                if opcodeString == b'21':
                    return instructionSize, format_instr(instr, mnemonic, operand1, "[" + operand2 + "]")
                else:
                    return instructionSize, format_instr(instr, mnemonic, operand2, "dword [" + operand1 + "]")
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            else:
                #instruction size is 2 (opcode + modrm)
                instructionSize = 2

                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = opcodeLookup[opcodeString][0]
                operand1 = x86RegLookup[reg]
                operand2 = x86RegLookup[rm]
            
            if opcodeString == b'23':
                return instructionSize, format_instr(instr, mnemonic, operand1, "[" + operand2 + "]")
            else:
                return instructionSize, format_instr(instr, mnemonic, "[" + operand2 +"]", operand1)
        
        if mod == '01':
            log.info("[r/m + byte]")
            
            #instruction size is 3 (opcode + modrm + byte)
            instructionSize = 3
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = opcodeLookup[opcodeString][0]
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm] + " + " + byteString[4:].decode("utf-8")
            
            if opcodeString == b'23':
                return instructionSize, format_instr(instr, mnemonic, operand1, "[" + operand2 + "]")
            else:
                return instructionSize, format_instr(instr, mnemonic, "[" + operand2 +"]", operand1)
        
        if mod == '10':
            log.info("r/m + dword")

            #instruction size is 6 (opcode + modrm + dword)
            instructionSize = 6
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = opcodeLookup[opcodeString][0]
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm] + " + 0x" + flipDword(byteString[4:]).decode("utf-8")

            if opcodeString == b'23':
                return instructionSize, format_instr(instr, mnemonic, operand1, "dword [" + operand2 + "]")
            else:
                return instructionSize, format_instr(instr, mnemonic, "dword [" + operand2 +"]", operand1)
        
        if mod == '11':
            log.info("r/m")

            #instruction size is 2 (opcode + modrm)
            instructionSize = 2

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = opcodeLookup[opcodeString][0]
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm]

            if opcodeString == b'23':
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
            else:
                return instructionSize, format_instr(instr, mnemonic, operand2, operand1)

    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/and

#call   TODO offset tracking
def parse_call(instr, inbytes, currentOffset):
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
    
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)
    #e8
    if opcodeString == b'e8' or opcodeString == b'E8':
        
        #instruction size is fixed (5, opcode + id dword)
        instructionSize = 5
        for x in range(currentOffset + 1, currentOffset + opcodeLookup[opcodeString][3]):
            instr.append(inbytes[x])
        
        log.info("parse_call::Found 0xE8")
        byteString = binascii.hexlify(instr)
        log.info(byteString)
        mnemonic = opcodeLookup[opcodeString][0]
        
        #calculate the call offset
    
        cd = flipDword(byteString[2:])                                                          #extract cd and flip the dword
        callOffset = (hex((int(cd, 16) + currentOffset + instructionSize) & 0xFFFFFFFF))        #aksjfsajlhfsakjfhsaf
        operand1 = "offset_" + callOffset[2:].zfill(8) +"h"                                      #pretty
        log.info(operand1)                                      
        log.info("CurrentOffset = " + str(currentOffset))           
        offsetIncrement = instructionSize
        return offsetIncrement, format_instr(instr, mnemonic, operand1)
    #/e8    

    #ff
    elif opcodeString == b'ff' or opcodeString == b'FF':
        
        
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))

        #if /1 this is dec r/m32
        if reg == '001':
            return parse_dec(origInstruction, inbytes, currentOffset)

        #if /2 this is inc r/m32
        if reg == '000':
            return parse_inc(origInstruction, inbytes, currentOffset)

        elif reg == '010':
            log.info("parse_call:ff confirmed /2")

        log.info("parse_add:Found 0xff")

     #[r/m]
        if mod == '00':
            log.info("[r/m]")
            log.info(opcodeString)
            
            #[disp 32]
            if rm == '101':
                log.info("[disp 32]")
                
                #instruction size = 6 (opcode + modrm + dword)
                instructionSize = 6
                
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "call"
                operand1 = "[dword 0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            #[not special case]
            else:
                
                #read in remaining bytes, instruction size is the default 6 (opcode + modrm + imm32)
                instructionSize = 6
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])

                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "call"
                operand1 = "[" + x86RegLookup[rm] + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
        
        elif mod == '01':
            log.info("[r/m + byte]")

            #instruction size = 3 (opcode + modrm + byte)
            instructionSize = 3

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "call"
            operand1 = "[byte " + x86RegLookup[rm] + " + 0x" + byteString[4:6].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)

        elif mod == '10':
            log.info("[r/m + dword]")

            #instruction size = 6 (opcode + modrm + dword)
            instructionSize = 6

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "call"
            operand1 = "[dword " + x86RegLookup[rm] + " + 0x" + byteString[4:12].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)
        elif mod == '11':
            log.info("r/m")

            #instruction size = 2 (opcode + modrm)
            instructionSize = 2

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "call"
            operand1 = x86RegLookup[rm]
            return instructionSize, format_instr(instr, mnemonic, operand1)   
    #/ff

    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/call

#clflush
def parse_clflush(instr, inbytes, currentOffset):
    log.info("parse_clflush: found 0x0f")
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
    
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)

    #add 'AE' byte to instruction
    instr.append(inbytes[currentOffset + 1])

    #examine byte 2
    byte2 = binascii.hexlify(instr)[2:4]

    #if byte 2 is af this is imul r32. r/m32
    if byte2 == b'af':
        return parse_imul(origInstruction, inbytes, currentOffset)
    
    elif byte2 == b'ae':
        log.info("parse_clflush:confirmed AE")

    #add modrm bit to instruction
    instr.append(inbytes[currentOffset + 2])
    modrm = binascii.hexlify(instr)[4:]
    mod, reg, rm = parse_modrm(modrm)
    log.info("MOD: " + str(mod))
    log.info("REG: " + str(reg))
    log.info("RM: " + str(rm))

    if mod == '00':
        
        if rm == '101':
            log.info("parse_clflush: [disp32]")
            
            #instructionSize = 7 (opcode + AE + modrm + dword)
            instructionSize = 7

            #read remaining bytes
            for x in range(currentOffset + 3, currentOffset + instructionSize):
                instr.append(inbytes[x])

            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "clflush"
            operand1 = "[0x" + flipDword(byteString[6:]).decode("utf-8") + "]"
            return instructionSize, format_instr(instr, mnemonic, operand1)   
            
        #illegal RM
        elif rm == '100':
            log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
            log.info(opcodeString)
            mnemonic = 'db 0x' + opcodeString.decode("utf-8")
            return 1, format_instr(instr, mnemonic)

        else:
            log.info("parse_clflush: [r/m]")

            #instructionSize = 3 (opcode + AE + modrm)
            instructionSize = 3

            #read remaining bytes
            for x in range(currentOffset + 3, currentOffset + instructionSize):
                instr.append(inbytes[x])

            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "clflush"
            operand1 = "[" + x86RegLookup[rm] + "]"
            return instructionSize, format_instr(instr, mnemonic, operand1)  

    elif mod == '01':
        log.info("parse_clflush:r/m + byte")
        #instructionSize = 4 (opcode + AE + modrm + byte)
        instructionSize = 4

        #read remaining bytes
        for x in range(currentOffset + 3, currentOffset + instructionSize):
            instr.append(inbytes[x])

        #hexlify the instruction and extract elements
        byteString = binascii.hexlify(instr)
        mnemonic = "clflush"
        operand1 = "[byte 0x" + byteString[6:].decode("utf-8") + "]"
        return instructionSize, format_instr(instr, mnemonic, operand1) 
    
    elif mod == '10':
        log.info("parse_clflush:r/m + dword")
        #instructionSize = 7 (opcode + AE + modrm + dword)
        instructionSize = 7

        #read remaining bytes
        for x in range(currentOffset + 3, currentOffset + instructionSize):
            instr.append(inbytes[x])

        #hexlify the instruction and extract elements
        byteString = binascii.hexlify(instr)
        mnemonic = "clflush"
        operand1 = "[dword 0x" + flipDword(byteString[6:]).decode("utf-8") + "]"
        return instructionSize, format_instr(instr, mnemonic, operand1) 
    
    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/clflush

#dec
def parse_dec(instr, inbytes, currentOffset):
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
    
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)
    
    #ff
    if opcodeString == b'ff' or opcodeString == b'FF':
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))
        
        #if /2 this is call r/m32
        if reg == '010':
            return parse_call(origInstruction, inbytes, currentOffset)
        
        #if this is /0 then inc r/m32
        if reg == '000':
            return parse_inc(origInstruction, inbytes, currentOffset)

        elif reg == '001':
            log.info("parse_dec:ff confirmed /1")

        log.info("parse_dec:Found 0xff")

        #[r/m]
        if mod == '00':
            
            log.info(opcodeString)
            
            #[disp 32]
            if rm == '101':
                log.info("[disp 32]")
                
                #instruction size = 6 (opcode + modrm + dword)
                instructionSize = 6
                
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "dec"
                operand1 = "[dword 0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            #[not special case]
            else:
                log.info("[r/m]")

                #instruction size is 2 (opcode + modrm)
                instructionSize = 2
                #read in remaining bytes, instruction size is the default 6 (opcode + modrm + imm32)
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])

                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "dec"
                operand1 = "[" + x86RegLookup[rm] + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
        
        elif mod == '01':
            log.info("[r/m + byte]")

            #instruction size = 3 (opcode + modrm + byte)
            instructionSize = 3

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "dec"
            operand1 = "[byte " + x86RegLookup[rm] + " + 0x" + byteString[4:6].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)

        elif mod == '10':
            log.info("[r/m + dword]")

            #instruction size = 6 (opcode + modrm + dword)
            instructionSize = 6

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "dec"
            operand1 = "[dword " + x86RegLookup[rm] + " + 0x" + byteString[4:12].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)
        elif mod == '11':
            log.info("r/m")

            #instruction size = 6 (opcode + modrm + imm32)
            instructionSize = 2

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "dec"
            operand1 = x86RegLookup[rm]
            return instructionSize, format_instr(instr, mnemonic, operand1) 
    #/ff

    #48 - 4f
    else:
        #instruction size is 1 byte (opcode + rd)
        instructionSize = 1

        #hexlify the instruction and extract elements
        byteString = binascii.hexlify(instr)
        mnemonic = "dec"
        operand1 = x86RegLookup[opcodeLookup[byteString][2]]
        return instructionSize, format_instr(instr, mnemonic, operand1) 
        
    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/dec

#idiv
def parse_idiv(instr, inbytes, currentOffset):
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
    
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)
    
    #add modrm bit to instruction
    instr.append(inbytes[currentOffset + 1])
    modrm = binascii.hexlify(instr)[2:]
    mod, reg, rm = parse_modrm(modrm)
    
    
    #if /5 this is imul r/m32
    if reg == '101':
        return parse_imul(origInstruction, inbytes, currentOffset)

    elif reg == '111':
        log.info("parse_idiv:ff confirmed /7")

    log.info("parse_idiv:Found 0xff")
    log.info("MOD: " + str(mod))
    log.info("REG: " + str(reg))
    log.info("RM: " + str(rm))

    #[r/m]
    if mod == '00':
        
        log.info(opcodeString)
        
        #[disp 32]
        if rm == '101':
            log.info("[disp 32]")
            
            #instruction size = 6 (opcode + modrm + dword)
            instructionSize = 6
            
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "idiv"
            operand1 = "[dword 0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
            return instructionSize, format_instr(instr, mnemonic, operand1)
        
        #illegal RM
        elif rm == '100':
            log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
            log.info(opcodeString)
            mnemonic = 'db 0x' + opcodeString.decode("utf-8")
            return 1, format_instr(instr, mnemonic)

        #[not special case]
        else:
            log.info("[r/m]")

            #instruction size is 2 (opcode + modrm)
            instructionSize = 2
            #read in remaining bytes, instruction size is the default 6 (opcode + modrm + imm32)
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])

            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "idiv"
            operand1 = "[" + x86RegLookup[rm] + "]"
            return instructionSize, format_instr(instr, mnemonic, operand1)
    
    elif mod == '01':
        log.info("[r/m + byte]")

        #instruction size = 3 (opcode + modrm + byte)
        instructionSize = 3

        #read in remaining bytes
        for x in range(currentOffset + 2, currentOffset + instructionSize):
            instr.append(inbytes[x])
        
        #hexlify the instruction and extract elements
        byteString = binascii.hexlify(instr)
        mnemonic = "idiv"
        operand1 = "[byte " + x86RegLookup[rm] + " + 0x" + byteString[4:6].decode("utf-8") +"]"
        return instructionSize, format_instr(instr, mnemonic, operand1)

    elif mod == '10':
        log.info("[r/m + dword]")

        #instruction size = 6 (opcode + modrm + dword)
        instructionSize = 6

        #read in remaining bytes
        for x in range(currentOffset + 2, currentOffset + instructionSize):
            instr.append(inbytes[x])
        
        #hexlify the instruction and extract elements
        byteString = binascii.hexlify(instr)
        mnemonic = "idiv"
        operand1 = "[dword " + x86RegLookup[rm] + " + 0x" + byteString[4:12].decode("utf-8") +"]"
        return instructionSize, format_instr(instr, mnemonic, operand1)
    elif mod == '11':
        log.info("r/m")

        #instruction size = 6 (opcode + modrm + imm32)
        instructionSize = 2

        #read in remaining bytes
        for x in range(currentOffset + 2, currentOffset + instructionSize):
            instr.append(inbytes[x])
        
        #hexlify the instruction and extract elements
        byteString = binascii.hexlify(instr)
        mnemonic = "idiv"
        operand1 = x86RegLookup[rm]
        return instructionSize, format_instr(instr, mnemonic, operand1)
    
    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/idiv

#imul
def parse_imul(instr, inbytes, currentOffset):
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
    
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)

    #f7
    if opcodeString == b'f7' or opcodeString == b'F7':
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        
        #if /7 this is idiv r/m32
        if reg == '111':
            return parse_idiv(origInstruction, inbytes, currentOffset)

        elif reg == '101':
            log.info("parse_imul:ff confirmed /5")

        log.info("parse_imul:Found 0xff")
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))
        
        #[r/m]
        if mod == '00':
            
            log.info(opcodeString)
            
            #[disp 32]
            if rm == '101':
                log.info("[disp 32]")
                
                #instruction size = 6 (opcode + modrm + dword)
                instructionSize = 6
                
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "imul"
                operand1 = "[dword 0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            #[not special case]
            else:
                log.info("[r/m]")

                #instruction size is 2 (opcode + modrm)
                instructionSize = 2
                #read in remaining bytes, instruction size is the default 6 (opcode + modrm + imm32)
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])

                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "imul"
                operand1 = "[" + x86RegLookup[rm] + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
        
        elif mod == '01':
            log.info("[r/m + byte]")

            #instruction size = 3 (opcode + modrm + byte)
            instructionSize = 3

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = "[byte " + x86RegLookup[rm] + " + 0x" + byteString[4:6].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)

        elif mod == '10':
            log.info("[r/m + dword]")

            #instruction size = 6 (opcode + modrm + dword)
            instructionSize = 6

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = "[dword " + x86RegLookup[rm] + " + 0x" + byteString[4:12].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)
        elif mod == '11':
            log.info("r/m")

            #instruction size = 6 (opcode + modrm + imm32)
            instructionSize = 2

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = x86RegLookup[rm]
            return instructionSize, format_instr(instr, mnemonic, operand1)
    #/f7

    #0f
    if opcodeString == b'0f' or opcodeString == b'0F':
        #save a copy of instr before operating
        origInstruction = bytearray()
        origInstruction.append(inbytes[currentOffset])
        
        #Hexlify the opcode
        opcodeString = binascii.hexlify(instr)

        #add 'AE' byte to instruction
        instr.append(inbytes[currentOffset + 1])

        #examine byte 2
        byte2 = binascii.hexlify(instr)[2:4]

        #if byte 2 is af this is clflush m8
        if byte2 == b'ae':
            return parse_clflush(origInstruction, inbytes, currentOffset)
        
        elif byte2 == b'af':
            log.info("parse_imul:confirmed AE")
        
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 2])
        modrm = binascii.hexlify(instr)[4:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))

        if mod == '00':
            
            if rm == '101':
                log.info("parse_add:[disp32]")

                #instruction size is 7 (opcode + byte2 + modrm + dword)
                instructionSize = 7
            
                #read in remaining bytes
                for x in range(currentOffset + 3, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "imul"
                operand1 = "dword [0x" + flipDword(byteString[6:]).decode("utf-8") + "]"
                operand2 = x86RegLookup[reg]

                return instructionSize, format_instr(instr, mnemonic, operand2, operand1)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            else:
                #instruction size is 3 (opcode + byte2 + modrm)
                instructionSize = 3

                #read in remaining bytes
                for x in range(currentOffset + 3, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "imul"
                operand1 = x86RegLookup[reg]
                operand2 = "dword [" + x86RegLookup[rm] + "]"
            
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
                
        if mod == '01':
            log.info("[r/m + byte]")
            
            #instruction size is 3 (opcode + modrm + byte)
            instructionSize = 3
            #read in remaining bytes
            for x in range(currentOffset + 3, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = x86RegLookup[reg]
            operand2 = "dword [byte "+ x86RegLookup[rm] + " + " + byteString[4:].decode("utf-8") + "]"
            
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)
        
        if mod == '10':
            log.info("r/m + dword")

            #instruction size is 7 (opcode + byte2 + modrm + dword)
            instructionSize = 7
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = x86RegLookup[reg]
            operand2 = "dword [dword " + x86RegLookup[rm] + " + 0x" + flipDword(byteString[4:]).decode("utf-8") + "]"

            return instructionSize, format_instr(instr, mnemonic, operand1, "dword [" + operand2 + "]")
            
        if mod == '11':
            log.info("r/m")

            #instruction size is 3 (opcode + byte2 + modrm)
            instructionSize = 3

            #read in remaining bytes
            for x in range(currentOffset + 3, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm]

            return instructionSize, format_instr(instr, mnemonic, operand1, operand2)     
    #/0f

    #69
    if opcodeString == b'69':
        
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:4]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))

        if mod == '00':
            
            if rm == '101':
                log.info("parse_add:[disp32]")

                #instruction size is 10 (opcode + modrm + dword + imm32)
                instructionSize = 10
            
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "imul"
                operand1 = x86RegLookup[reg]
                operand2 = "dword [0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
                operand3 = "0x" + flipDword(byteString[12:]).decode("utf-8")

                return instructionSize, format_instr(instr, mnemonic, operand1, operand2, operand3)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            else:
                #instruction size is 6 (opcode + modrm + imm32)
                instructionSize = 6

                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "imul"
                operand1 = x86RegLookup[reg]
                operand2 = "dword [" + x86RegLookup[rm] + "]"
                operand3 = "0x" + flipDword(byteString[4:]).decode("utf-8")
            
                return instructionSize, format_instr(instr, mnemonic, operand1, operand2, operand3)
                
        if mod == '01':
            log.info("[r/m + byte]")
            
            #instruction size is 7 (opcode + modrm + byte + imm32)
            instructionSize = 7
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = x86RegLookup[reg]
            operand2 = "dword [byte "+ x86RegLookup[rm] + " + " + byteString[4:6].decode("utf-8") + "]"
            operand3 = "0x" + flipDword(byteString[6:]).decode("utf-8")
                        
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2, operand3)
        
        if mod == '10':
            log.info("r/m + dword")

            #instruction size is 10 (opcode + modrm + dword + imm32)
            instructionSize = 10
            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = x86RegLookup[reg]
            operand2 = "dword [dword " + x86RegLookup[rm] + " + 0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
            operand3 = "0x" + flipDword(byteString[12:]).decode("utf-8")

            return instructionSize, format_instr(instr, mnemonic, operand1, operand2, operand3)
            
        if mod == '11':
            log.info("r/m")

            #instruction size is 6 (opcode + modrm + imm32)
            instructionSize = 6

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "imul"
            operand1 = x86RegLookup[reg]
            operand2 = x86RegLookup[rm]
            operand3 = "0x" + flipDword(byteString[4:]).decode("utf-8")
            
            return instructionSize, format_instr(instr, mnemonic, operand1, operand2, operand3)   
    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/imul

#inc
def parse_inc(instruction, inbytes, currentOffset):
    #save a copy of instr before operating
    origInstruction = bytearray()
    origInstruction.append(inbytes[currentOffset])
    
    #Hexlify the opcode
    opcodeString = binascii.hexlify(instr)

    #ff
    if opcodeString == b'ff' or opcodeString == b'FF':
        
        #add modrm bit to instruction
        instr.append(inbytes[currentOffset + 1])
        modrm = binascii.hexlify(instr)[2:]
        mod, reg, rm = parse_modrm(modrm)
        log.info("MOD: " + str(mod))
        log.info("REG: " + str(reg))
        log.info("RM: " + str(rm))
                
        #if /2 this is call r/m32
        if reg == '010':
            return parse_call(origInstruction, inbytes, currentOffset)

        #if /1 this is dec rm32
        elif reg == '001':
            return parse_dec(origInstruction, inbytes, currentOffset)
        
        elif reg == '000':
            log.info("parse_inc:ff confirmed /0")

        log.info("parse_inc:Found 0xff")

        #[r/m]
        if mod == '00':
            
            log.info(opcodeString)
            
            #[disp 32]
            if rm == '101':
                log.info("[disp 32]")
                
                #instruction size = 6 (opcode + modrm + dword)
                instructionSize = 6
                
                #read in remaining bytes
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])
                
                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "inc"
                operand1 = "[dword 0x" + flipDword(byteString[4:12]).decode("utf-8") + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
            
            #illegal RM
            elif rm == '100':
                log.info("Illegal Combo: mod==00 and rm==100, implying SIB byte.")
                log.info(opcodeString)
                mnemonic = 'db 0x' + opcodeString.decode("utf-8")
                return 1, format_instr(instr, mnemonic)

            #[not special case]
            else:
                log.info("[r/m]")

                #instruction size is 2 (opcode + modrm)
                instructionSize = 2
                #read in remaining bytes, instruction size is the default 6 (opcode + modrm + imm32)
                for x in range(currentOffset + 2, currentOffset + instructionSize):
                    instr.append(inbytes[x])

                #hexlify the instruction and extract elements
                byteString = binascii.hexlify(instr)
                mnemonic = "inc"
                operand1 = "[" + x86RegLookup[rm] + "]"
                return instructionSize, format_instr(instr, mnemonic, operand1)
        
        elif mod == '01':
            log.info("[r/m + byte]")

            #instruction size = 3 (opcode + modrm + byte)
            instructionSize = 3

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "inc"
            operand1 = "[byte " + x86RegLookup[rm] + " + 0x" + byteString[4:6].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)

        elif mod == '10':
            log.info("[r/m + dword]")

            #instruction size = 6 (opcode + modrm + dword)
            instructionSize = 6

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "inc"
            operand1 = "[dword " + x86RegLookup[rm] + " + 0x" + byteString[4:12].decode("utf-8") +"]"
            return instructionSize, format_instr(instr, mnemonic, operand1)
        elif mod == '11':
            log.info("r/m")

            #instruction size = 6 (opcode + modrm + imm32)
            instructionSize = 2

            #read in remaining bytes
            for x in range(currentOffset + 2, currentOffset + instructionSize):
                instr.append(inbytes[x])
            
            #hexlify the instruction and extract elements
            byteString = binascii.hexlify(instr)
            mnemonic = "inc"
            operand1 = x86RegLookup[rm]
            return instructionSize, format_instr(instr, mnemonic, operand1) 
    #/ff

    #40 - 47
    else:
        #instruction size is 1 byte (opcode + rd)
        instructionSize = 1

        #hexlify the instruction and extract elements
        byteString = binascii.hexlify(instr)
        mnemonic = "dec"
        operand1 = x86RegLookup[opcodeLookup[byteString][2]]
        return instructionSize, format_instr(instr, mnemonic, operand1) 

    #base case: return db
    mnemonic = 'db 0x' + opcodeString.decode("utf-8")
    return 1, format_instr(instr, mnemonic)
#/inc

def parse(instruction, inbytes, currentOffset):
    log.info("parse::Instruction: " + str(binascii.hexlify(instruction)))
    byteString= binascii.hexlify(instruction)
    if byteString in opcodeLookup:
        log.info("Found opcode " + byteString.decode("utf-8") + ":" + opcodeLookup[byteString][1])
        method_to_call = "parse_" + opcodeLookup[byteString][0]
        log.info("Calling parser " + method_to_call)
        offsetIncrement, result = eval(method_to_call + "(instruction, inbytes, currentOffset)")        
        if result:
            return offsetIncrement, result
        #parsers = [parse_int3, parse_cpuid, parse_add, parse_fake_mov]
        #for p in parsers:
        #    result = p(instruction)
        #    if result:
        #    return result
    mnemonic = 'db 0x' + opcodeString.decode("utf-8") 
    return 1, format_instr(instr, mnemonic)


if '__main__' == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help='Input file', dest='infile',
                        required=True)
    parser.add_argument('-v', '--verbose', help='Enable verbose output',
                        action='store_true', default=False)
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    log.debug('Attempting to read input file')
    try:
        with open(args.infile, 'rb') as fd:
            inbytes = bytearray(fd.read())
            if not inbytes:
                log.error('Input file was empty')
                sys.exit(-1)
    except (IOError, OSError) as e:
        log.error('Failed to open {}'.format(args.infile))
        sys.exit(-1)

    #print(inbytes)
    #print(len(inbytes))

    log.debug('Parsing instructions')
    offset = 0
    instr = bytearray()
    instructions = []
    jumpToOffsets = []                                                      #aggregate offsets jumped-to
    offset = 0
    while offset < len(inbytes):
        b=inbytes[offset]
        instr=bytearray()
        instr.append(b)
        opcodeString = binascii.hexlify(instr)
        log.debug('Testing instruction: {}'.format(binascii.hexlify(instr)))
        offsetIncrement, result = parse(instr, inbytes, offset)
        if result:
            #Code for incrementing offset and 
            byteString = binascii.hexlify(instr)
            offset += offsetIncrement
            #OG offset increment
                #offset += opcodeLookup[opcodeString][3]
                #instr_offset = offset + 1 - len(instr)
                #instr_offset = offset + 1 - opcodeLookup[opcodeString][3]
            instr_offset = offset - offsetIncrement
            log.info('Adding instruction for offset {}'.format(instr_offset))
            instructions.append((instr_offset, result))
            instr = bytearray()
        else:
            offset += 1

    log.debug('Creating output data')
    output = ''
    for (offset, text) in instructions:
        output += '{:08x}:   {}\n'.format(offset, text)

    log.debug('Attempting to write output')
    print(output)
