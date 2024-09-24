rule MAL_EXE_GULoader_Sep_24 : EXE LOADER {
      meta:
        description = "This rule detects GULoader malware samples."
        author      = "Michelle Khalil"
        date        = "2024-09-24"
        sharing     = "TLP:CLEAR"
        tags        = "windows,exe,loader"
        hunting     = "https://hybrid-analysis.com/yara-search/results/13e5c878722edcb979aeb6e8afd3b5315306ee84e4b6cb7f843b7119b650ab2d"
        sample      = "2b5098eda716be0a7cedf56acb2ccd19b977301ac6a9677d182c997eb1787ffe"
        os          = "windows"
        category    = "Malware" 
    strings:
      $s1 = {6A 1C 8D 45 [3-8] E8 [4] 8B 45 ?? A9 F0 FF FF FF 75 ?? 81 7D ?? EF BE AD DE 75 ?? 81 7D ?? 49 6E 73 74 75 ?? 81 7D ?? 73 6F 66 74 75 ?? 81 7D ?? 4E 75 6C 6C 75 ?? 09 45 08 8B 45 08 8B 0D [4] 83 E0 02 09 05 [4] 8B 45 ?? 3B C6 89 0D [4] 0F 8? [2] 00 00 F6 45 08 08 75 06 F6 45 08 04 75}
           //  push         0x1C                                                                  
           //  lea          eax, [ebp-0x28]                                                       
           //  push         ebx                                                                   
           //  push         eax                                                                   
           //  call         sub_405ddb()                                                          
           //  mov          eax, [ebp-0x28]                                                       
           //  test         eax, 0xFFFFFFF0                                                       
           //  jnz          .6                                                                    
           //  cmp          dword ptr [ebp-0x24], 0xDEADBEEF                                      
           //  jnz          .6                                                                    
           //  cmp          dword ptr [ebp-0x18], 0x74736E49                                      
           //  jnz          .6                                                                    
           //  cmp          dword ptr [ebp-0x1C], 0x74666F73                                      
           //  jnz          .6                                                                    
           //  cmp          dword ptr [ebp-0x20], 0x6C6C754E                                      
           //  jnz          .6                                                                    
           //  or           [ebp+0x08], eax                                                       
           //  mov          eax, [ebp+0x08]                                                       
           //  mov          ecx, [0x41D438]                                                       
           //  and          eax, 0x02                                                             
           //  or           [0x42F0C0], eax                                                       
           //  mov          eax, [ebp-0x10]                                                       
           //  cmp          eax, esi                                                              
           //  mov          [0x42F034], ecx                                                       
           //  jnbe         .11                                                                   
           //  test         byte ptr [ebp+0x08], 0x08                                             
           //  jnz          .4                                                                    
           //  test         byte ptr [ebp+0x08], 0x04   
 condition:
        uint16(0) == 0x5A4D and all of them
}
