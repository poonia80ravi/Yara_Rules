rule MAL_Daxin_Feb_2022_1 : rootkit daxin x64 core
{
   meta:
        description = "Detect the Daxin rootkit"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage"
        date = "2022-02-28"
        hash1 = "06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4"
        hash2 = "8d9a2363b757d3f127b9c6ed8f7b8b018e652369bc070aa3500b3a978feaa6ce"
        hash3 = "6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f"
        tlp = "Clear"
        adversary = "Chinese espionage APT"
   strings:
        $s1 = { 48 8d 15 [4-7] 48 8d 4c 24 40 ff 15 [5] 8d [5] 4c 8d 44 24 40 ?? 89 ?? 24 30 41 b9 09 00 00 00 [0-2] 48 8b [1-3] c6 44 24 28 00 83 64 24 20 00 ff 15 }
        $s2 = { c7 44 24 50 30 00 00 00 ?? 89 ?? 24 58 }
        $s3 = { 48 83 ec 28 83 62 30 00 48 8b ca 33 d2 ff 15 [2] 00 00 33 c0 48 83 c4 28 c3 cc cc cc cc cc cc }
        $s4 = { 8b ?? 49 8b c9 ff 15 [2] 00 00 85 c0 }
   condition:
        uint16(0) == 0x5A4D and filesize > 30KB and 3 of ($s*) 
}
