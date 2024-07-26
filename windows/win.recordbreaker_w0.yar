import "pe"

rule win_recordbreaker_w0 {
    meta:
        description = "Detect variants of Raccoon Stealer v2"
        author = "Jake Goldi"
        date = "2022-09-20"
        hash1 = "022432f770bf0e7c5260100fcde2ec7c49f68716751fd7d8b9e113bf06167e03"
        version="1.0"
        phase = "experimental"
        url = "https://d01a.github.io/raccoon-stealer/#iocs"
        references = "https://www.zscaler.com/blogs/security-research/raccoon-stealer-v2-latest-generation-raccoon-family"
        source = "https://raw.githubusercontent.com/taogoldi/YARA/main/stealers/raccoon/raccoon_stealer.yara"
        credits = "@0xd01a"
        malware = "Win32.PWS.Raccoon"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.recordbreaker"
        malpedia_rule_date = "20220921"
        malpedia_hash = ""
        malpedia_version = "20220921"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
  strings:
        $s1 = "ffcookies.txt" wide ascii nocase
        $s2 = "wallet.dat" wide ascii nocase
        $s3 = "ru" wide ascii nocase
        $s4 = "record" wide ascii nocase

        /*
        E8 CC 11 00 00                          call    mw_rc4_decrypt
        6A 55                                   push    85              ; cchLocaleName
        8D 8D 1C FF FF FF                       lea     ecx, [ebp-0E4h]
        89 45 D8                                mov     [ebp-28h], eax
        A1 50 E0 4F 00                          mov     eax, GetUserDefaultLocaleName
        51                                      push    ecx             ; lpLocaleName
        FF D0                                   call    eax ; GetUserDefaultLocaleName
        85 C0                                   test    eax, eax
        74 24                                   jz      short loc_4F75B5
        BE 00 E0 4F 00
        */
        $op1 = { e8 cc 11 00 00 6a 55 8d 8d 1c ff ff ff 89 45 d8 a1 50 e0 ?? 00 51 ff d0 85 c0 74 24 be 00 e0 ?? 00 }
        /* 
        8B 3D 90 E0 4F 00       mov     edi, lstrlenW
        8B DA                   mov     ebx, edx
        53                      push    ebx             ; lpString
        89 4D FC                mov     [ebp+lpString], ecx
        FF D7                   call    edi ; lstrlenW
        FF 75 FC                push    [ebp+lpString]  ; lpString
        8B F0                   mov     esi, eax
        FF D7                   call    edi ; lstrlenW
        8B 0D 48 E0 4F 00       mov     ecx, LocalAlloc
        8D B8 80 00 00 00       lea     edi, [eax+80h]
        03 FE                   add     edi, esi
        8D 04 3F                lea     eax, [edi+edi]
        50                      push    eax             ; uBytes
        6A 40                   push    64              ; uFlags
        FF D1                   call    ecx ; LocalAlloc
        */
        $op2 = { 8b 3d 90 e0 ?? 00 8b da 53 89 4d fc ff d7 ff 75 fc 8b f0 ff d7 8b 0d 48 e0 ?? 00 8d b8 80 00 00 00 03 fe 8d 04 3f 50 6a 40 ff d1 } 

    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and ((2 of ($s*)) and (all of ($op*)))

}
