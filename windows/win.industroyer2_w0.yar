// Created by Nozomi Networks Labs

rule win_industroyer2_w0 {
    meta:
        author = "Nozomi Networks Labs"
        name = "Industroyer2"
        description = "Industroyer2 malware targeting power grid components."
        actor = "Sandworm"
        source="https://www.nozominetworks.com/downloads/US/Nozomi-Networks-WP-Industroyer2.pdf"
        hash = "D69665F56DDEF7AD4E71971F06432E59F1510A7194386E5F0E8926AEA7B88E00"

        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industroyer2"
        malpedia_rule_date = "20220905"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220905"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "%02d:%lS" wide ascii
        $s2 = "PService_PPD.exe" wide ascii
        $s3 = "D:\\OIK\\DevCounter" wide ascii
        $s4 = "MSTR ->> SLV" fullword wide ascii
        $s5 = "MSTR <<- SLV" fullword wide ascii
        $s6 = "Current operation : %s"
        $s7 = "Switch value: %s"
        $s8 = "Unknown APDU format !!!"
        $s9 = "Length:%u bytes |"
        $s10 = "Sent=x%X | Received=x%X"
        $s11 = "ASDU:%u | OA:%u | IOA:%u |"
        $s12 = "Cause: %s (x%X) | Telegram type: %s (x%X)"

    condition:
        5 of them
}

