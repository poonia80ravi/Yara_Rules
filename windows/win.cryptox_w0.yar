import "pe"
rule win_crytox_w0 {
  meta:
    description = "Detect variants of Crytox Ransomware"
    author = "Jake Goldi"
    date = "2022-09-29"
    packed_hash1 = "32eef267a1192a9a739ccaaae0266bc66707bb64768a764541ecb039a50cba67"
    hash2 = "11ea0d7e0ebe15b8147d39e72773221d11c2cf84e2d8d6164102c65e797eef6d"
    hash3 = "68fae79a2eca125090bd2a8badc46ed4324c38f2ff24db702d09c3d7687e0047"
    hash4 = "a0a6c2937b6a8b2bc1214ace8255adc6992b553b9e740c3fe1543e089e8437aa"
    source = "https://raw.githubusercontent.com/taogoldi/YARA/main/ransomware/crytox_ransom.yara"
    
    version="1.0"
    phase = "experimental"
    url = "https://www.zscaler.com/blogs/security-research/technical-analysis-crytox-ransomware"
    malware = "Win64.Ransom.Crytox"
    
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crytox"
    malpedia_rule_date = "20220930"
    malpedia_hash = ""
    malpedia_version = "20220930"
    malpedia_license = "CC BY-SA 4.0"
    malpedia_sharing = "TLP:WHITE"
    
    
  strings:
    $s1 = "utox" wide ascii nocase
    /*
        hash 2: 11ea0d7e0ebe15b8147d39e72773221d11c2cf84e2d8d6164102c65e797eef6d

        FF 15 C9 22 00 00                       call    cs:GlobalAlloc
        48 89 85 58 FF FF FF                    mov     [rbp+hMem], rax ; unk_5F2520
        4C 8B E0                                mov     r12, rax
        
        48 8B C8                                mov     rcx, rax

        E8 DD 13 00 00                          call    sub_1402E940E
        48 C7 C1 C0 01 00 00                    mov     rcx, 448
        49 8D 94 24 08 04 00 00                 lea     rdx, [r12+408h]

        4C 8D 05 29 20 00 00                    lea     r8, unk_1402EA070
 
        4C 8D 8D A4 FD FF FF                    lea     r9, [rbp+var_25C]
        E8 A2 11 00 00                          call    sub_1402E91F5
        48 8B 8D 58 FF FF FF                    mov     rcx, [rbp+hMem] ; hMem
        FF 15 90 22 00 00                       call    cs:GlobalFree 

        -------------   

        hash 3: 68fae79a2eca125090bd2a8badc46ed4324c38f2ff24db702d09c3d7687e0047

        FF 15 C9 22 00 00                       call    cs:GlobalAlloc
        48 89 85 58 FF FF FF                    mov     [rbp+hMem], rax
        4C 8B E0                                mov     r12, rax
        
        90                                      nop
        50                                      push    rax
        59                                      pop     rcx
        
        E8 E2 13 00 00                          call    sub_1402E9413
        48 C7 C1 C0 01 00 00                    mov     rcx, 1C0h
        49 8D 94 24 08 04 00 00                 lea     rdx, [r12+408h]

        4C 8D 05 29 20 00 00                    lea     r8, unk_1402EA070
        
        4C 8D 8D A4 FD FF FF                    lea     r9, [rbp+var_25C]
        E8 A7 11 00 00                          call    sub_1402E91FA
        48 8B 8D 58 FF FF FF                    mov     rcx, [rbp+hMem] ; hMem
        FF 15 90 22 00 00                       call    cs:GlobalFree

        ------------- 

        hash 4: a0a6c2937b6a8b2bc1214ace8255adc6992b553b9e740c3fe1543e089e8437aa

        FF 15 C9 22 00 00                       call    cs:GlobalAlloc
        48 89 85 58 FF FF FF                    mov     [rbp+hMem], rax
        4C 8B E0                                mov     r12, rax
        48 8B C8                                mov     rcx, rax
        E8 61 12 00 00                          call    sub_1402E9292
        48 C7 C1 C0 01 00 00                    mov     rcx, 1C0h
        49 8D 94 24 08 04 00 00                 lea     rdx, [r12+408h]
        4C 8D 05 29 20 00 00                    lea     r8, unk_1402EA070
        4C 8D 8D A4 FD FF FF                    lea     r9, [rbp+var_25C]
        E8 26 10 00 00                          call    sub_1402E9079
        48 8B 8D 58 FF FF FF                    mov     rcx, [rbp+hMem] ; hMem
        FF 15 90 22 00 00                       call    cs:GlobalFre



    */

    $op1 = { FF 15 C9 22 00 00 48 89 85 58 FF FF FF 4C 8B E0 } 
    $op2 = { E8 ?? ?? 00 00 48 C7 C1 C0 01 00 00 49 8D 94 24 08 04 00 00 }
    $op3 = { 4C 8D 05 29 20 00 00 }
    $op4 = { 4C 8D 8D A4 FD FF FF E8 ?? 1? 00 00 48 8B 8D 58 FF FF FF FF 15 90 22 00 00 }

condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and ((all of ($s*)) and (all of ($op*)))

}
