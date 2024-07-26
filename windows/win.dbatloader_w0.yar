rule win_dbatloader_w0 {

    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2021-10-12"
        version = "1"
        description = "Detects cryptographic routine"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dbatloader"
        malpedia_rule_date = "20211012"
        malpedia_hash = ""
        malpedia_version = "20211012"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        /*
                                      loc_413930:
        8D 45 E4                      lea     eax, [ebp+var_1C]
        8B 55 F8                      mov     edx, [ebp+var_8]
        8A 54 1A FF                   mov     dl, [edx+ebx-1]
        0F B7 CF                      movzx   ecx, di
        C1 E9 08                      shr     ecx, 8
        32 D1                         xor     dl, cl
        */
        $xor_decrypt = { 8D 45 E4  8B 55 F8  8A 54 1A FF  0F B7 CF  C1 E9 08  32 D1 }

    condition:
        all of them
}
