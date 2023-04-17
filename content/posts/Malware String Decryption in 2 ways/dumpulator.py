from dumpulator import Dumpulator
dp = Dumpulator("loki.dump", quiet = "TRUE" )

dp.regs.ecx = 0x004eac00
dp.regs.edx = 0x30f
dp.call(0x004b9b50,[0x004f8a4c, 0x004f8a34 ])

decrypted_string = dp.read(0x004eac00, 0x30f)\
print(decrypted_string.decode('latin-1'))
