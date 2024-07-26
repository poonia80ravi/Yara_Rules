import "pe"

rule win_bhunt_w0 {
    meta:
        description = "Detects BHunt Malware Infostealer"
        author = "BlackBerry Research & Intelligence Team"
        date = "Jan 28th 2022"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bhunt"
        malpedia_version = "20220220"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        malpedia_rule_date = "20220220"
        malpedia_hash = ""
        
    strings:
        // C2
        $s1 = "http://minecraftsquid.hopto.org/ifo.php" wide
        // Name of assembly in metadata
        $s2 = "BHUNT" wide
        // Outlook misspelled in reg key
        $s3 = "Outllook" wide

    condition:
        // MZ Header
        uint16(0) == 0x5a4d and
        // is a .NET binary
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size != 0 and
        all of ($s*)
}
