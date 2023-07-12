mov ebx,0x565562a2
call ebx

mov esi, 0x56559008
mov edi, 0xffffca18

rep movs BYTE PTR es:[edi], BYTE PTR es:[esi]

mov eax, 0xffffca18
push eax
mov ebx,0x56556286
call ebx