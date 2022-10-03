# Unmapping PE files, fixing Alignment and Fixing corrupted/Missing PE Header

![image pe](pe.png)
# Steps

1) first add the correct pe header : look for 4c 01 (cpu architecture 386 in optional header ) open the corrupted file and a known good file and copy and paste till 4c01 (use HxD)
2) unmap :  a) make the virtual address section match the raw addres section (PE bear)
            b) set the raw size and virual size correct formula VA of section 2 - VA of section 1
            c) make reloc size 0

3) check and fix section allignment : move to raw address of  section  1 . is the byte zeroed out correctly till the start if not add 00 bytes till the start example  of adding 00 using hxd


 

