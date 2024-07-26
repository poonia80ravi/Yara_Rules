rule win_misha_w0 {

    meta:
        author = "Daniel Plohmann"
        description = "Detect the unpacked payload for win.misha."
        date = "20211109"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.misha"
        malpedia_rule_date = "20211009"
        malpedia_hash = ""
        malpedia_version = "20211009"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        /*  @0x4252d7 - creating a heap buffer for the config
            8D 44 24 0C                   lea     eax, [esp+10h+var_4]
            68 CE 11 01 00                push    111CEh
            50                            push    eax
            BF 40 9F 01 00                mov     edi, 19F40h
            B9 58 D8 42 00                mov     ecx, offset inner_buffer
            8B C6                         mov     eax, esi
            89 7C 24 14                   mov     [esp+18h+var_4], edi
            E8 1C D4 FF FF                call    sub_422712
            59                            pop     ecx
            59                            pop     ecx
            85 C0                         test    eax, eax
            0F 85 A1 00 00 00             jnz     loc_4253A1
        */
        $config_heap_0 = {8D4424?? 68???????? 50 BF???????? B9???????? 8BC689?????? E8???????? 59 59 85C0 0F }

        /*  @0x425300 - creating a heap buffer for some x64 code
            8D 44 24 0C                   lea     eax, [esp+10h+var_4]
            68 91 F3 00 00                push    0F391h
            50                            push    eax
            8D 86 40 9F 01 00             lea     eax, [esi+19F40h]
            B9 28 EA 43 00                mov     ecx, offset inner_buffer_2
            C7 44 24 14 80 03 02 00       mov     [esp+18h+var_4], 20380h
            E8 F0 D3 FF FF                call    sub_422712
            59                            pop     ecx
            59                            pop     ecx
            85 C0                         test    eax, eax
            75 79                         jnz     short loc_4253A1
        */
        $config_heap_1 = { 8D4424?? 68???????? 50 8D86???????? B9???????? C74424?????????? E8???????? 59 59 85C0 75 }

        /*  @0x408549 - string decryption
            8B 45 F8                      mov     eax, [ebp+var_8]
            33 D2                         xor     edx, edx
            F7 75 14                      div     [ebp+dwKeyLen]
            8B 45 10                      mov     eax, [ebp+szKey]
            0F B6 0C 10                   movzx   ecx, byte ptr [eax+edx]
            8B 45 F8                      mov     eax, [ebp+var_8]
            33 D2                         xor     edx, edx
            BE 00 01 00 00                mov     esi, 100h
            F7 F6                         div     esi
            33 CA                         xor     ecx, edx
            8B 45 FC                      mov     eax, [ebp+var_4]
            03 45 F8                      add     eax, [ebp+var_8]
            0F B6 00                      movzx   eax, byte ptr [eax]
            33 C1                         xor     eax, ecx
            8B 4D FC                      mov     ecx, [ebp+var_4]
            03 4D F8                      add     ecx, [ebp+var_8]
            88 01                         mov     [ecx], al
            EB BF                         jmp     short loc_40853A
        */
        $string_decrypt = { 8B45?? 33D2 F7???? 8B45?? 0FB6???? 8B45?? 33D2 BE00010000 F7F6 33CA 8B45?? 0345?? 0FB6?? 33C1 8B4D?? 034D?? 8801 EB }
        
    condition:
        any of them
}
