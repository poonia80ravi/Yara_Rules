rule win_tinba_w0 {
    meta:
        author = "n3sfox <n3sfox@gmail.com>"
        date = "2015/11/07"
        description = "Tinba 2 (DGA) banking trojan"
        reference = "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world"
        filetype = "memory"
        hash = "c7f662594f07776ab047b322150f6ed0"
        hash = "dc71ef1e55f1ddb36b3c41b1b95ae586"
        hash = "b788155cb82a7600f2ed1965cffc1e88"
        source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/tinba2.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinba"
        malpedia_version = "20170605"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $str3 = "NtCreateUserProcess"
        $str4 = "NtQueryDirectoryFile"
        $str5 = "RtlCreateUserThread"
        $str6 = "DeleteUrlCacheEntry"
        $str7 = "PR_Read"
        $str8 = "PR_Write"
        $pubkey = "BEGIN PUBLIC KEY"
        $code1 = {50 87 44 24 04 6A ?? E8}

    condition:
        all of ($str*) and $pubkey and $code1
}
