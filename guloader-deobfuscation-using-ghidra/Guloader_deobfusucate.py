#TODO write a description for this script
#@irfan_eternal 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


from ghidra.program.disassemble import Disassembler
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.lang import OperandType
from ghidra.program.disassemble import Disassembler
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import  Address, AddressSet
from ghidra.program.model.lang import OperandType
from ghidra.app.plugin.assembler import Assemblers
import struct
 

dis = Disassembler.getDisassembler(currentProgram, ConsoleTaskMonitor(), None)
mem = currentProgram.getMemory()
listing = currentProgram.getListing()

def handleSingleStepException(): 
    address_array = findBytes(currentProgram.getMinAddress(), b'\\\x9c\\\x89', 1000)
    for addr in address_array:
        try:
           dis.disassemble(addr, None)
           theinstruction = getInstructionAt(addr)
           for i in  range(5) :
               theinstruction = theinstruction.getNext();
               ##print(theinstruction.getAddress().toString())
           
           exception_addr = theinstruction.getAddress()
           math_addr = exception_addr.add(2)
           math_byte = mem.getByte(math_addr)
           math_byte = math_byte & 0xFF
           eip_displacement = math_byte ^ 0x6A
           eip_displacement = eip_displacement - 2
           patch_instruction = bytearray()
           patch_instruction.append(0xeb)
           patch_instruction.append(eip_displacement)
           patch_instruction2 = bytes(patch_instruction)
           clearListing(exception_addr)
           block = mem.getBlock(exception_addr)
           block.putBytes(exception_addr,patch_instruction2)
           dis.disassemble(exception_addr, None) 
           exceptioninstruction = getInstructionAt(exception_addr)
           jmpaddress = exceptioninstruction.getDefaultFlows()[0]
           jmpaddress2 = jmpaddress
           for j in range(100):
               clearListing(jmpaddress2)
               jmpaddress2 = jmpaddress2.add(1)
           
           dis.disassemble(jmpaddress, None)    
        
   
        except:
            continue
        
def handlesingleBreak(addr):
        exception_addr = addr
        ##print("working on "+ addr.toString())
        math_addr = addr.add(1)
        ##print(math_addr)
        math_byte = mem.getByte(math_addr)
        math_byte = math_byte & 0xFF
        ##print(math_byte)
        eip_displacement = math_byte ^ 0x6A
        eip_displacement = eip_displacement - 2
        patch_instruction = bytearray()
        patch_instruction.append(0xeb)
        patch_instruction.append(eip_displacement)
        patch_instruction2 = bytes(patch_instruction)
        exception_addr = addr
        clearListing(exception_addr)
        next_addr = exception_addr.add(1)
        clearListing(next_addr)
        block = mem.getBlock(exception_addr)
        block.putBytes(exception_addr,patch_instruction2)
        dis.disassemble(exception_addr, None)
        exceptioninstruction = getInstructionAt(exception_addr)
        jmpaddress = exceptioninstruction.getDefaultFlows()[0]
        jmpaddress2 = jmpaddress
        for k in range(100):
               clearListing(jmpaddress2)
               jmpaddress2 = jmpaddress2.add(1)
           
        dis.disassemble(jmpaddress, None)
    
def handleBreakpointException():
    address_array2 = []
    cuIterator = currentProgram.getListing().getCodeUnits(True)
    while(cuIterator.hasNext()):
        cu = cuIterator.next()
        if (cu.getMnemonicString() == "INT3"):
            address_array2.append(cu.getMinAddress())
            
    for addr in address_array2:
        exception_addr = addr
        ##print("working on "+ addr.toString())
        math_addr = addr.add(1)
        ##print(math_addr)
        math_byte = mem.getByte(math_addr)
        math_byte = math_byte & 0xFF
        ##print(math_byte)
        eip_displacement = math_byte ^ 0x6A
        eip_displacement = eip_displacement - 2
        patch_instruction = bytearray()
        patch_instruction.append(0xeb)
        patch_instruction.append(eip_displacement)
        patch_instruction2 = bytes(patch_instruction)
        exception_addr = addr
        clearListing(exception_addr)
        next_addr = exception_addr.add(1)
        clearListing(next_addr)
        block = mem.getBlock(exception_addr)
        block.putBytes(exception_addr,patch_instruction2)
        dis.disassemble(exception_addr, None)
        exceptioninstruction = getInstructionAt(exception_addr)
        jmpaddress = exceptioninstruction.getDefaultFlows()[0]
        jmpaddress2 = jmpaddress
        for k in range(100):
               clearListing(jmpaddress2)
               jmpaddress2 = jmpaddress2.add(1)
           
        dis.disassemble(jmpaddress, None)  
    
    
handleSingleStepException();
handleBreakpointException();

def handlememoryviolationException():
    inst = getInstructionAt(currentProgram.getMinAddress())
    dis.disassemble(currentProgram.getMinAddress(), None)
    
    address_array3 = []
    
    while(inst.getAddress() != toAddr("0x190ba")):
            mn =inst.getMnemonicString()
            if mn == "PUSH":
                nxtinst = inst.getNext()
                nxtmn = nxtinst.getMnemonicString()
                if nxtmn == "MOV" :   
                    pushoprerand1 = inst.getDefaultOperandRepresentation(0)
                    movoprerand1 = nxtinst.getDefaultOperandRepresentation(0)
                    if pushoprerand1 == movoprerand1 and  inst.getOperandType(0) == OperandType.REGISTER and nxtinst.getOperandType(0) == OperandType.REGISTER and nxtinst.getOperandType(1) == OperandType.SCALAR:
                        for k in range(40):
                            jmpaddress = nxtinst.getAddress()
                            jmpaddress2 = jmpaddress
                            clearListing(jmpaddress2)
                            jmpaddress2 = jmpaddress2.add(1)
               
                        dis.disassemble(jmpaddress, None)  
                        ##print(inst.getAddress())
                        result = nxtinst.getDefaultOperandRepresentation(1)
                        result = int(result[2:],16)
                        nxtinst = nxtinst.getNext()
                        nxtmn = nxtinst.getMnemonicString()
                        mn_allowed = ["ADD", "XOR", "SUB"]
                        while (nxtmn in mn_allowed):
                            if (nxtmn == "ADD" and nxtinst.getOperandType(1) == OperandType.SCALAR) :
                                change = nxtinst.getDefaultOperandRepresentation(1)
                                change = int(change[2:],16)
                                result += change
                                nxtinst = nxtinst.getNext()
                                nxtmn = nxtinst.getMnemonicString()
                                continue;
                            elif (nxtmn == "XOR" and nxtinst.getOperandType(1) == OperandType.SCALAR):
                                change = nxtinst.getDefaultOperandRepresentation(1)
                                change = int(change[2:],16)
                                result ^= change  
                                nxtinst = nxtinst.getNext()
                                nxtmn = nxtinst.getMnemonicString()
                                continue;
                            elif (nxtmn == "SUB"  and nxtinst.getOperandType(1) == OperandType.SCALAR):
                                change = nxtinst.getDefaultOperandRepresentation(1)
                                change = int(change[2:],16)
                                result -= change
                                nxtinst = nxtinst.getNext()
                                nxtmn = nxtinst.getMnemonicString()
                                continue;
        
                        
                        ##print(inst.getAddress())
                        result = result & 0xFFFFFFFF
                        hex_result= hex(result)
                        ##print(hex_result)
                        setEOLComment(inst.getAddress(),hex_result)
                        if result  == 0:
                            address_array3.append(nxtinst.getAddress())
                            ##print()
                        inst = inst.getNext();
                        continue;
                    else:
                        inst = inst.getNext();
                        continue;
                            
                        
                else:
                    inst = inst.getNext();
                    continue; 
                    
                 
                        
            else:
                inst = inst.getNext()   
                continue; 
    
        
        
    for addr in address_array3:
            exception_addr = addr
            ##print("working on "+ addr.toString())
            math_addr = addr.add(2)
            ##print(math_addr)
            math_byte = mem.getByte(math_addr)
            math_byte = math_byte & 0xFF
            ##print(math_byte)
            eip_displacement = math_byte ^ 0x6A
            eip_displacement = eip_displacement - 2
            patch_instruction = bytearray()
            patch_instruction.append(0xeb)
            patch_instruction.append(eip_displacement)
            patch_instruction2 = bytes(patch_instruction)
            exception_addr = addr
            clearListing(exception_addr)
            next_addr = exception_addr.add(1)
            clearListing(next_addr)
            block = mem.getBlock(exception_addr)
            block.putBytes(exception_addr,patch_instruction2)
            dis.disassemble(exception_addr, None)
            exceptioninstruction = getInstructionAt(exception_addr)
            jmpaddress = exceptioninstruction.getDefaultFlows()[0]
            jmpaddress2 = jmpaddress
            for k in range(100):
                   clearListing(jmpaddress2)
                   jmpaddress2 = jmpaddress2.add(1)
               
            dis.disassemble(jmpaddress, None) 

   
handlememoryviolationException();
handleSingleStepException   
handleBreakpointException(); 
    
    


string_enc_fun =  findBytes(currentProgram.getMinAddress(), b'\x8b\x54\\\x24\x04', 100);  #edx
string_enc_fun +=  findBytes(currentProgram.getMinAddress(), b'\x8b\x44\\\x24\x04', 100);  #eax
string_enc_fun +=  findBytes(currentProgram.getMinAddress(), b'\x8b\x5c\\\x24\x04', 100);  #ebx
string_enc_fun +=  findBytes(currentProgram.getMinAddress(), b'\x8b\x4c\\\x24\x04', 100);  #ecx
string_enc_fun +=  findBytes(currentProgram.getMinAddress(), b'\x8b\x44\\\x24\\\x28', 100);  #eax



def string_decryption(address):
        jmpaddress2 = address
        for k in range(100):
            clearListing(jmpaddress2)
            jmpaddress2 = jmpaddress2.add(1)
        dis.disassemble(address, None) 
        str_inst = listing.getInstructionAt(address)        
        reg = str_inst.getRegister(0).getName()
        ##print(reg)
        str_inst = str_inst.getNext()
        counter = 0
        while (counter < 1000) :
            mn= str_inst.getMnemonicString()
            if (str_inst.getMnemonicString() == "MOV" and  str_inst.getDefaultOperandRepresentation(0) == "dword ptr ["+reg+"]" and str_inst.getOperandType(1) == OperandType.SCALAR  ):
                ##print(str_inst.getAddress())
                break
            elif (str_inst.getMnemonicString() == "INT3"):
                excep_addr =  str_inst.getAddress()
                ##print(str_inst)
                handlesingleBreak(excep_addr)
                str_inst = listing.getInstructionAt(excep_addr)
                ##print(str_inst)
                ##print("int3 changed to JMP")
                ##print(str_inst)
                continue
                
            elif (str_inst.getMnemonicString() == "CALL" and  len(str_inst.getDefaultFlows()) == 1 ):
                ##print(str_inst.getAddress())
                counter +=1
                ret_inst = str_inst.getNext()
                ret_addr = ret_inst.getAddress()
                call_addr = str_inst.getDefaultFlows()[0]
                if  (listing.isUndefined(call_addr,call_addr)):
                    dis.disassemble(call_addr, None)
                str_inst = listing.getInstructionAt(call_addr)
                if (str_inst.getMnemonicString() == "POP"):
                    if str_inst.getNext().getMnemonicString() == "JMP":
                        str_inst = listing.getInstructionAt(ret_addr) 
                continue
                
            elif (str_inst.getMnemonicString() == "JMP"):
                 counter +=1
                 jmp_addr = str_inst.getDefaultFlows()[0]
                 str_inst = listing.getInstructionAt(jmp_addr)
                 continue
            
            elif mn == "PUSH":
                    inst = str_inst
                    nxtinst = inst.getNext()
                    nxtmn = nxtinst.getMnemonicString()
                    if nxtmn == "MOV" :   
                        pushoprerand1 = inst.getDefaultOperandRepresentation(0)
                        movoprerand1 = nxtinst.getDefaultOperandRepresentation(0)
                        if pushoprerand1 == movoprerand1 and  inst.getOperandType(0) == OperandType.REGISTER and nxtinst.getOperandType(0) == OperandType.REGISTER and nxtinst.getOperandType(1) == OperandType.SCALAR:
                            for k in range(100):
                                jmpaddress = nxtinst.getAddress()
                                jmpaddress2 = jmpaddress
                                clearListing(jmpaddress2)
                                jmpaddress2 = jmpaddress2.add(1)
                   
                            dis.disassemble(jmpaddress, None)  
                            ##print(inst.getAddress())
                            result = nxtinst.getDefaultOperandRepresentation(1)
                            result = int(result[2:],16)
                            nxtinst = nxtinst.getNext()
                            nxtmn = nxtinst.getMnemonicString()
                            mn_allowed = ["ADD", "XOR", "SUB"]
                            while (nxtmn in mn_allowed):
                                if (nxtmn == "ADD" and nxtinst.getOperandType(1) == OperandType.SCALAR) :
                                    change = nxtinst.getDefaultOperandRepresentation(1)
                                    change = int(change[2:],16)
                                    result += change
                                    nxtinst = nxtinst.getNext()
                                    nxtmn = nxtinst.getMnemonicString()
                                    continue;
                                elif (nxtmn == "XOR" and nxtinst.getOperandType(1) == OperandType.SCALAR):
                                    change = nxtinst.getDefaultOperandRepresentation(1)
                                    change = int(change[2:],16)
                                    result ^= change  
                                    nxtinst = nxtinst.getNext()
                                    nxtmn = nxtinst.getMnemonicString()
                                    continue;
                                elif (nxtmn == "SUB"  and nxtinst.getOperandType(1) == OperandType.SCALAR):
                                    change = nxtinst.getDefaultOperandRepresentation(1)
                                    change = int(change[2:],16)
                                    result -= change
                                    nxtinst = nxtinst.getNext()
                                    nxtmn = nxtinst.getMnemonicString()
                                    continue;
            
                            
                            ##print(inst.getAddress())
                            result = result & 0xFFFFFFFF
                            hex_result= hex(result)
                            ##print(hex_result)
                            setEOLComment(inst.getAddress(),hex_result)
                            if result  == 0:
                                addr = nxtinst.getAddress()
                                exception_addr = addr
                                ##print("working on "+ addr.toString())
                                math_addr = addr.add(2)
                                ##print(math_addr)
                                math_byte = mem.getByte(math_addr)
                                math_byte = math_byte & 0xFF
                                ##print(math_byte)
                                eip_displacement = math_byte ^ 0x6A
                                eip_displacement = eip_displacement - 2
                                patch_instruction = bytearray()
                                patch_instruction.append(0xeb)
                                patch_instruction.append(eip_displacement)
                                patch_instruction2 = bytes(patch_instruction)
                                exception_addr = addr
                                clearListing(exception_addr)
                                next_addr = exception_addr.add(1)
                                clearListing(next_addr)
                                block = mem.getBlock(exception_addr)
                                block.putBytes(exception_addr,patch_instruction2)
                                dis.disassemble(exception_addr, None)
                                exceptioninstruction = getInstructionAt(exception_addr)
                                jmpaddress = exceptioninstruction.getDefaultFlows()[0]
                                jmpaddress2 = jmpaddress
                                for k in range(40):
                                       clearListing(jmpaddress2)
                                       jmpaddress2 = jmpaddress2.add(1)
                                   
                                dis.disassemble(jmpaddress, None)
                                str_inst = listing.getInstructionAt(exception_addr)
                                ##print(str_inst)
                                
                                
                            else:
                                str_inst = str_inst.getNext()
                                counter +=1
                                continue
                                
                        else:
                             str_inst = str_inst.getNext()
                             counter +=1
                             continue
                                    
                    else:
                        str_inst = str_inst.getNext()
                        counter +=1
                        continue        
            
            
            
            else:
                counter +=1
                str_inst = str_inst.getNext() 
        if (counter > 990):
            #print("counter_limit_exceeded") 
            return 0,0
        else:        
            result = str_inst.getOpObjects(1)[0].getValue()
            str_inst = str_inst.getNext()
            final_result = []
            counter = 0
            while ( counter < 10000): 
                ##print(str_inst.getAddress())
                mn= str_inst.getMnemonicString()
                if (mn == "MOV" and  str_inst.getDefaultOperandRepresentation(0) == "dword ptr ["+reg+"]" and str_inst.getOperandType(1) == OperandType.SCALAR ):
                    counter +=1
                    ###print(str_inst)
                    final_result.append(hex( result & 0xFFFFFFFF))
                    result = str_inst.getOpObjects(1)[0].getValue()
                    ##print(result)
                    str_inst = str_inst.getNext()
                    continue
                
                elif mn =="RET":
                    final_result.append(hex( result & 0xFFFFFFFF))
                    ##print("break 2")
                    break
                
                elif (str_inst.getMnemonicString() == "INT3"):
                    excep_addr =  str_inst.getAddress()
                    #print(str_inst)
                    handlesingleBreak(excep_addr)
                    str_inst = listing.getInstructionAt(excep_addr)
                    #print(str_inst)
                    ##print("int3 changed to JMP")
                    ##print(str_inst)
                    continue
                
                elif (mn == "CALL"):
                    counter +=1
                    str_inst2 = str_inst
                    ret_inst = str_inst.getNext()
                    ret_addr = ret_inst.getAddress()
                    call_addr = str_inst.getDefaultFlows()[0]
                    if  (listing.isUndefined(call_addr,call_addr)):
                        dis.disassemble(call_addr, None)
                    str_inst = listing.getInstructionAt(call_addr)
                    ##print(str_inst)
                    ##print(str_inst.getAddress())
                    if (str_inst.getMnemonicString() == "POP"):
                        ##print("pop")
                        nxt = str_inst.getNext()
                        ##print(nxt)
                        if nxt.getMnemonicString() == "JMP":
                            str_inst = listing.getInstructionAt(ret_addr) 
                            ##print("return")
                            ##print(ret_addr)
                    continue
                    
                elif ( mn == "JMP"):
                     counter +=1
                     jmpaddress = str_inst.getDefaultFlows()[0]
                     jmpaddress2 = jmpaddress
                     for k in range(100):
                                clearListing(jmpaddress2)
                                jmpaddress2 = jmpaddress2.add(1)
                   
                     dis.disassemble(jmpaddress, None)  
                     ##print("jmp")
                     ##print(jmp_addr)
                     str_inst = listing.getInstructionAt(jmpaddress)
                     
                     ##print(str_inst)
                     
                     continue
                 
                elif (mn == "ADD" and  str_inst.getDefaultOperandRepresentation(0) == "dword ptr ["+reg+"]" and str_inst.getOperandType(1) == OperandType.SCALAR):
                                    counter +=1
                                    change = str_inst.getDefaultOperandRepresentation(1)
                                    change = int(change[2:],16)
                                    result += change
                                    str_inst = str_inst.getNext()
                                    continue;
                elif (mn == "XOR" and  str_inst.getDefaultOperandRepresentation(0) == "dword ptr ["+reg+"]" and str_inst.getOperandType(1) == OperandType.SCALAR):
                                    change = str_inst.getDefaultOperandRepresentation(1)
                                    counter +=1
                                    change = int(change[2:],16)
                                    result ^= change  
                                    str_inst = str_inst.getNext()
                                    continue;
                elif (mn == "SUB"  and  str_inst.getDefaultOperandRepresentation(0) == "dword ptr ["+reg+"]" and str_inst.getOperandType(1) == OperandType.SCALAR):
                                    change = str_inst.getDefaultOperandRepresentation(1)
                                    counter +=1
                                    change = int(change[2:],16)
                                    result -= change
                                    str_inst = str_inst.getNext()
                                    continue;             
                elif mn == "PUSH":
                    inst = str_inst
                    nxtinst = inst.getNext()
                    nxtmn = nxtinst.getMnemonicString()
                    if nxtmn == "MOV" :   
                        pushoprerand1 = inst.getDefaultOperandRepresentation(0)
                        movoprerand1 = nxtinst.getDefaultOperandRepresentation(0)
                        if pushoprerand1 == movoprerand1 and  inst.getOperandType(0) == OperandType.REGISTER and nxtinst.getOperandType(0) == OperandType.REGISTER and nxtinst.getOperandType(1) == OperandType.SCALAR:
                            for k in range(100):
                                jmpaddress = nxtinst.getAddress()
                                jmpaddress2 = jmpaddress
                                clearListing(jmpaddress2)
                                jmpaddress2 = jmpaddress2.add(1)
                   
                            dis.disassemble(jmpaddress, None)  
                            ##print(inst.getAddress())
                            result = nxtinst.getDefaultOperandRepresentation(1)
                            result = int(result[2:],16)
                            nxtinst = nxtinst.getNext()
                            nxtmn = nxtinst.getMnemonicString()
                            mn_allowed = ["ADD", "XOR", "SUB"]
                            while (nxtmn in mn_allowed):
                                if (nxtmn == "ADD" and nxtinst.getOperandType(1) == OperandType.SCALAR) :
                                    change = nxtinst.getDefaultOperandRepresentation(1)
                                    change = int(change[2:],16)
                                    result += change
                                    nxtinst = nxtinst.getNext()
                                    nxtmn = nxtinst.getMnemonicString()
                                    continue;
                                elif (nxtmn == "XOR" and nxtinst.getOperandType(1) == OperandType.SCALAR):
                                    change = nxtinst.getDefaultOperandRepresentation(1)
                                    change = int(change[2:],16)
                                    result ^= change  
                                    nxtinst = nxtinst.getNext()
                                    nxtmn = nxtinst.getMnemonicString()
                                    continue;
                                elif (nxtmn == "SUB"  and nxtinst.getOperandType(1) == OperandType.SCALAR):
                                    change = nxtinst.getDefaultOperandRepresentation(1)
                                    change = int(change[2:],16)
                                    result -= change
                                    nxtinst = nxtinst.getNext()
                                    nxtmn = nxtinst.getMnemonicString()
                                    continue;
            
                            
                            ##print(inst.getAddress())
                            result = result & 0xFFFFFFFF
                            hex_result= hex(result)
                            ##print(hex_result)
                            setEOLComment(inst.getAddress(),hex_result)
                            if result  == 0:
                                addr = nxtinst.getAddress()
                                exception_addr = addr
                                ##print("working on "+ addr.toString())
                                math_addr = addr.add(2)
                                ##print(math_addr)
                                math_byte = mem.getByte(math_addr)
                                math_byte = math_byte & 0xFF
                                ##print(math_byte)
                                eip_displacement = math_byte ^ 0x6A
                                eip_displacement = eip_displacement - 2
                                patch_instruction = bytearray()
                                patch_instruction.append(0xeb)
                                patch_instruction.append(eip_displacement)
                                patch_instruction2 = bytes(patch_instruction)
                                exception_addr = addr
                                clearListing(exception_addr)
                                next_addr = exception_addr.add(1)
                                clearListing(next_addr)
                                block = mem.getBlock(exception_addr)
                                block.putBytes(exception_addr,patch_instruction2)
                                dis.disassemble(exception_addr, None)
                                exceptioninstruction = getInstructionAt(exception_addr)
                                jmpaddress = exceptioninstruction.getDefaultFlows()[0]
                                jmpaddress2 = jmpaddress
                                for k in range(40):
                                       clearListing(jmpaddress2)
                                       jmpaddress2 = jmpaddress2.add(1)
                                   
                                dis.disassemble(jmpaddress, None)
                                str_inst = listing.getInstructionAt(exception_addr)
                                #print(str_inst)
                                
                                
                            else:
                                str_inst = str_inst.getNext()
                                counter +=1
                                continue
                                
                        else:
                             str_inst = str_inst.getNext()
                             counter +=1
                             continue
                                    
                    else:
                        str_inst = str_inst.getNext()
                        counter +=1
                        continue
                    
                    
                    
                    
                else:
                        str_inst = str_inst.getNext()
                        counter +=1
                        continue
                
                
            #print(str_inst.getAddress())
            len_string = final_result.pop(0)
            ###print(final_result)
            len_string = len_string [2:-1]
            len_string = int(len_string, 16)
            finalstring= ""
            for i in final_result:
                i = i[:-1]
                data = int(i,16)
                data_little = hex(struct.unpack("<I",struct.pack(">I", data ))[0])
                data_little = data_little[2:-1]
                if ( len(data_little) < 8):
                    for i in range(8 - len(data_little)):
                        data_little = "0" + data_little
                        
                    finalstring  += data_little
                        
                else:
                     finalstring  += data_little
                     ##print(finalstring)
            
                
            return finalstring, len_string
           
        
def xor(data, key):
            out = []
            for i in range(len(data)):
                out.append(data [i] ^ key[ i % len(key) ])
        
            return bytearray(out)
        
def xor_key(data, key):
            out = []
            for i in range(len(data)):
                out.append(data [i] ^ key[ i % len(key) ])
        
            payloadkey = ''
            for i in  out:
                payloadkey += hex(i)[2:]
            
            return payloadkey
key =  "506ee0400a3b2349834aca37b88e6942c746f62aeb1d85e8463a41f8146639ac366dbe33c3806411026e81b87a5a2b03c16f213786e33e8a3ae8ba706342"
key = bytearray.fromhex(key)


for i in string_enc_fun:
    try:
                #print(i)
                string, len_string = string_decryption(i)
                #print(string)
                if string != 0:
                    string = string [:len_string*2]
                    data = bytearray.fromhex(string)
                    if (500 < len_string and len_string < 1000 ) :
                        print("payload key length is : "+str(len_string)+ " key on the next line")
                        out= xor_key(data, key)
                        print(out)
                    
                    
                    
                    else:
                       out= xor(data, key)
                       #print(out.decode('latin1'))
                       setEOLComment(i,out.decode('latin1'))
        ##print(final_result)
    except AttributeError:
        while not (listing.isUndefined(i,i)):
            i = i.add(1)
        #print(i)
        jmpaddress = i
        jmpaddress2 = jmpaddress
        for k in range(100):
                clearListing(jmpaddress2)
                jmpaddress2 = jmpaddress2.add(1)
                   
        dis.disassemble(jmpaddress, None)
        
    except IndexError:
        handlememoryviolationException();
        handleSingleStepException   
        handleBreakpointException(); 
        

handleSingleStepException()           
handlememoryviolationException()    
handleBreakpointException();    
##string_decryption()
handleSingleStepException()          
handlememoryviolationException()    
handleBreakpointException();    
        
    

