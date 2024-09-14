rule MAL_EXE_Pikabot_sep_14 : EXE LOADER {
      meta:
        description = "This rule detects Pikabot loader malware samples of V1 & V2"
        author      = "Michelle Khalil"
        date        = "2024-09-14"
        sharing     = "TLP:CLEAR"
        tags        = "windows,exe,loader"
        sample      = "11cbb0233aff83d54e0d9189d3a08d02a6bbb0ffa5c3b161df462780e0ee2d2d"
        yara_hunt   = "https://www.hybrid-analysis.com/yara-search/results/84f9ce403fce4d1e0d6fffe7b53363ed4cd5beabe67d26acdf055914501f6fbc"
        reference   = "Internal Research"
        os          = "windows"
        category    = "Malware" 
    strings:
     
        $s1 = {8A 04 11 30 02 42 83 EE 01 75 F5 5E C3} 
        // 8A 04 11                                mov     al, [ecx+edx]
        // 30 02                                   xor     [edx], al
        // 42                                      inc     edx
        // 83 EE 01                                sub     esi, 1
        // 75 F5                                   jnz     short loc_1000168C
        // 5E                                      pop     esi
        // C3                                      retn

        $s2 = {C0 E9 02 C0 E0 04 [13] C0 E2 06 02 D0}
        // C0 E9 02                                shr     cl, 2
        // C0 E0 04                                shl     al, 4
        // 02 C8                                   add     cl, al
        // 88 0C 3E                                mov     [esi+edi], cl
        // 46                                      inc     esi
        // 8A 45 FF                                mov     al, [ebp+var_1]
        // 3C 40                                   cmp     al, 40h ; '@'
        // 74 09                                   jz      short loc_10001C32
        // C0 E2 06                                shl     dl, 6
        // 02 D0                                   add     dl, al

        $s3 = {8D 53 BF 80 FA 19 0F B6 C3 0F 47 C8}
        // 8D 53 BF                                lea     edx, [ebx-41h]
        // 80 FA 19                                cmp     dl, 19h
        // 0F B6 C3                                movzx   eax, bl
        // 0F 47 C8                                cmova   ecx, eax
        
        $s4 = { 89 45 10 83 7d f4 00 74 1a 8b 45 fc 8b 4d f8 8a 09 }
        //   89 45 10                 mov                 dword ptr [ebp + 0x10], eax
        //   83 7d f4 00               cmp                 dword ptr [ebp - 0xc], 0
        //   74 1a                   je                  0x1c
        //   8b 45 fc                 mov                 eax, dword ptr [ebp - 4]
        //   8b 4d f8                 mov                 ecx, dword ptr [ebp - 8]
        //   8a 09                   mov                 cl, byte ptr [ecx]    

        $s5 = { 8b 4d f8 8a 09 88 08 8b 45 fc }
        //   8b 4d f8                 mov                 ecx, dword ptr [ebp - 8]
        //   8a 09                   mov                 cl, byte ptr [ecx]
        //   88 08                   mov                 byte ptr [eax], cl
        //   8b 45 fc                 mov                 eax, dword ptr [ebp - 4]

        $s6 = { 40 89 45 fc 8b 45 f8 40 89 45 f8 eb d3 8b 45 08 }
        //   40                     inc                 eax
        //   89 45 fc                 mov                 dword ptr [ebp - 4], eax
        //   8b 45 f8                 mov                 eax, dword ptr [ebp - 8]
        //   40                     inc                 eax
        //   89 45 f8                 mov                 dword ptr [ebp - 8], eax
        //   eb d3                   jmp                 0xffffffd5
        //   8b 45 08                 mov                 eax, dword ptr [ebp + 8]

        $s7 = { 89 45 f8 eb d3 8b 45 08 c9 c3 55 }
        //   89 45 f8                 mov                 dword ptr [ebp - 8], eax
        //   eb d3                   jmp                 0xffffffd5
        //   8b 45 08                 mov                 eax, dword ptr [ebp + 8]
        //   c9                     leave               
        //   c3                     ret                 
        //   55                     push                ebp

        $s8 = { 83 ec 0c 8b 45 08 89 45 fc 8b 45 0c 89 45 f8 8b 45 10 }
        //   83 ec 0c                 sub                 esp, 0xc
        //   8b 45 08                 mov                 eax, dword ptr [ebp + 8]
        //   89 45 fc                 mov                 dword ptr [ebp - 4], eax
        //   8b 45 0c                 mov                 eax, dword ptr [ebp + 0xc]
        //   89 45 f8                 mov                 dword ptr [ebp - 8], eax
        //   8b 45 10                 mov                 eax, dword ptr [ebp + 0x10]

        $s9 = { 7c e9 8b 42 14 2b 42 0c 5f }
        //   7c e9                   jl                  0xffffffeb
        //   8b 42 14                 mov                 eax, dword ptr [edx + 0x14]
        //   2b 42 0c                 sub                 eax, dword ptr [edx + 0xc]
        //   5f                     pop                 edi

        $s10 = { e8???????? ffd0 c9 c3 55 8bec }
        //   e8????????                                 
        //   ffd0                   call                eax
        //   c9                     leave               
        //   c3                     ret                 
        //   55                     push                ebp
        //   8bec                   mov                 ebp, esp

        $s11 = { c9 c3 64a130000000 8b4018 c3 55 }
        //   c9                     leave               
        //   c3                     ret                 
        //   64a130000000           mov                 eax, dword ptr fs:[0x30]
        //   8b4018                 mov                 eax, dword ptr [eax + 0x18]
        //   c3                     ret                 
        //   55                     push                ebp


        $s12 = { 8A 44 0D C0 ?? ?? 88 84 0D ?? ?? FF FF 4? 83 ?? ?? 7C ?? [0-16] (C7 45   88 95) }
        // 8A 84 15 F4 FE FF FF                    mov     al, [ebp+edx+var10C]
        // 89 D1                                   mov     ecx, edx
        // 8A 94 1D F4 FE FF FF                    mov     dl, [ebp+ebx+var10C]
        // 88 94 0D F4 FE FF FF                    mov     [ebp+ecx+var10C], dl
        // 8B 55 08                                mov     edx, [ebp+arg0]
        // 88 84 1D F4 FE FF FF                    mov     [ebp+ebx+var10C], al
        // 02 84 0D F4 FE FF FF                    add     al, [ebp+ecx+var10C]
        // 0F B6 C0                                movzx   eax, al
        // 8A 84 05 F4 FE FF FF                    mov     al, [ebp+eax+var10C]
        // 32 04 32                                xor     al, [edx+esi]


        $s13 = { 8A 84 35 ?? ?? ?? ?? 8A 95 ?? ?? ?? ?? 88 84 1D ?? ?? ?? ?? 88 94 35 ?? ?? ?? ?? }
        // mov     al, [ebp+esi+var_118]
        // mov     dl, byte ptr [ebp+var_E7C]
        // mov     [ebp+ebx+var_118], al
        // inc     ebx
        // mov     [ebp+esi+var_118], dl   

        $s14 = { 8945f8 8b4510 8945f4 8b4510 48 }
        //   8945f8                 mov                 dword ptr [ebp - 8], eax
        //   8b4510                 mov                 eax, dword ptr [ebp + 0x10]
        //   8945f4                 mov                 dword ptr [ebp - 0xc], eax
        //   8b4510                 mov                 eax, dword ptr [ebp + 0x10]
        //   48                     dec                 eax

        $syscall_ZwQueryInfoProcess = { 68 9B 8B 16 88 E8 73 FF FF FF }
        $syscall_ZwCreateUserProcess = { 68 B2 CE 2E CF E8 5F FF FF FF }
        
 
        
        condition:
        uint16(0) == 0x5A4D and 10 of them
}
