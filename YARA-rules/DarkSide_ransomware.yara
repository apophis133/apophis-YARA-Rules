rule MAL_EXE_DarkSide_ransomware_Sep_26 : DarkSide_ransomware {
      meta:
        description = "This rule detects DarkSide_ransomware samples"
        author      = "Michelle khalil"
        date        = "2024-09-26"
        sharing     = "TLP:CLEAR"
        tags        = "windows,exe,ransomware"
        hunting     = "https://hybrid-analysis.com/yara-search/results/0cebf4529251211c76aff95f392935083e56e8eefddff388a20f20fe9e9639b6"
        sample      = "1cc7c198a8a2c935fd6f07970479e544f5b35a8eb3173de0305ebdf76a0988cb"
        os          = "windows"
        category    = "Malware" 
        strings:

        $s1 = { 66 C7 04 47 ?? ?? C7 44 47 02 ?? ?? ?? ?? C7 44 47 06 ?? ?? ?? ?? C7 44 47 0A ?? ?? ?? ?? C7 44 47 0E ?? ?? ?? ?? 66 C7 44 47 12 ?? ?? }
        //  66 C7 04 47 2A 00                               mov     word ptr [edi+eax*2], 2Ah ; '*'
        //  C7 44 47 02 72 00 65 00                         mov     dword ptr [edi+eax*2+2], 650072h
        //  C7 44 47 06 63 00 79 00                         mov     dword ptr [edi+eax*2+6], 790063h
        //  C7 44 47 0A 63 00 6C 00                         mov   dword ptr [edi+eax*2+0Ah], 6C0063h
        //  C7 44 47 0E 65 00 2A 00                         mov   dword ptr [edi+eax*2+0Eh], 2A0065h
        //  66 C7 44 47 12 00 00                            mov     word ptr [edi+eax*2+12h], 0


        $s2 = { 8B B5 0C FF FF FF 8B BD 08 FF FF FF 0F 10 06 0F 10 4E 10 0F 10 56 20 0F 10 5E 30 0F 11 07 0F 11 4F 10 0F 11 57 20 0F 11 5F 30 }
        //  8B B5 0C FF FF FF                               mov     esi, [ebp+var_F4]
        //  8B BD 08 FF FF FF                               mov     edi, [ebp+var_F8]
        //  0F 10 06                                        movups  xmm0, xmmword ptr [esi]
        //  0F 10 4E 10                                     movups  xmm1, xmmword ptr [esi+10h]
        //  0F 10 56 20                                     movups  xmm2, xmmword ptr [esi+20h]
        //  0F 10 5E 30                                     movups  xmm3, xmmword ptr [esi+30h]
        //  0F 11 07                                        movups  xmmword ptr [edi], xmm0
        //  0F 11 4F 10                                     movups  xmmword ptr [edi+10h], xmm1
        //  0F 11 57 20                                     movups  xmmword ptr [edi+20h], xmm2
        //  0F 11 5F 30                                     movups  xmmword ptr [edi+30h], xmm3

        $s3 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 51 52 56 57 8D 85 ?? ?? ?? ?? 50 FF 75 08 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        //  55                     push    ebp
        //  8B EC                  mov     ebp, esp
        //  81 EC ?? ?? ?? ??      sub     esp, some value
        //  53                     push    ebx
        //  51                     push    ecx
        //  52                     push    edx
        //  56                     push    esi
        //  57                     push    edi
        //  8D 85 ?? ?? ?? ??      lea     eax, [ebp+some value]
        //  50                     push    eax
        //  FF 75 08               push    [ebp+arg_0]
        //  E8 ?? ?? ?? ??         call    some function
        //  85 C0                  test    eax, eax
        //  0F 84 ?? ?? ?? ??      jz      loc_40535D
       
        condition:
        uint16(0) == 0x5A4D and
        2 of them 
        }
