rule win_originlogger_w0 {

    meta:
        author      = "Johannes Bader @viql"
        date        = "2022-09-20"
        description = "detects Orign Logger"
        tlp         = "TLP:WHITE"
        version     = "v1.0"
        hash_sha256 = "595a7ea981a3948c4f387a5a6af54a70a41dd604685c72cbd2a55880c2b702ed"
        hash_md5    = "bd9981b13c37d3ba04e55152243b1e3e"
        hash_sha1   = "4669160ec356a8640cef92ddbaf7247d717a3ef1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.originlogger"
        malpedia_rule_date = "20220920"
        malpedia_hash = ""
        malpedia_version = "20220920"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $name           = "OriginLogger" wide
        $exe            = "OriginLogger.exe" wide
        $cfg_section_0  = "[LOGSETTINGS]"
        $cfg_section_1  = "[ASSEMBLY]"
        $cfg_section_2  = "[STEALER]"
        $cfg_section_3  = "[BINDER]"
        $cfg_section_4  = "[INSTALLATION]"
        $cfg_section_5  = "[OPTIONS]"
        $cfg_section_6  = "[DOWNLOADER]"
        $cfg_section_7  = "[EXTENSION]"
        $cfg_section_8  = "[FILEPUMPER]"
        $cfg_section_9  = "[FAKEMSG]"
        $cfg_section_10 = "[HOST]"
        $cfg_section_11 = "[BUILD]"
        $cfg_entries_0  = "BinderON="
        $cfg_entries_1  = "blackhawk="
        $cfg_entries_2  = "centbrowser="
        $cfg_entries_3  = "chedot="
        $cfg_entries_4  = "citrio="
        $cfg_entries_5  = "clawsmail="
        $cfg_entries_6  = "CloneON="
        $cfg_entries_7  = "coccoc="
        $cfg_entries_8  = "Coolnovo="
        $cfg_entries_9  = "coowon="
        $cfg_entries_10 = "cyberfox="
        $cfg_entries_11 = "Delaysec="
        $cfg_entries_12 = "dest_date="
        $cfg_entries_13 = "Disablecp="
        $cfg_entries_14 = "Disablemsconfig="
        $cfg_entries_15 = "Disablesysrestore="
        $cfg_entries_16 = "DownloaderON="
        $cfg_entries_17 = "emclient="
        $cfg_entries_18 = "epicpb="
        $cfg_entries_19 = "estensionON="
        $cfg_entries_20 = "Eudora="
        $cfg_entries_21 = "falkon="
        $cfg_entries_22 = "FileassemblyON="
        $cfg_entries_23 = "FlashFXP="
        $cfg_entries_24 = "FPRadiobut="
        $cfg_entries_25 = "HostON="
        $cfg_entries_26 = "icecat="
        $cfg_entries_27 = "icedragon="
        $cfg_entries_28 = "IconON="
        $cfg_entries_29 = "IncrediMail="
        $cfg_entries_30 = "iridium="
        $cfg_entries_31 = "JustOne="
        $cfg_entries_32 = "kmeleon="
        $cfg_entries_33 = "kometa="
        $cfg_entries_34 = "liebao="
        $cfg_entries_35 = "orbitum="
        $cfg_entries_36 = "palemoon="
        $cfg_entries_37 = "pumderON="
        $cfg_entries_38 = "pumpertext="
        $cfg_entries_39 = "qqbrowser="
        $cfg_entries_40 = "screeninterval="
        $cfg_entries_41 = "SelectFolder="
        $cfg_entries_42 = "sleipnir="
        $cfg_entries_43 = "SmartLogger="
        $cfg_entries_44 = "smartLoggerType="
        $cfg_entries_45 = "SmartWords="
        $cfg_entries_46 = "sputnik="
        $cfg_entries_47 = "telegram_api="
        $cfg_entries_48 = "telegram_chatid="
        $cfg_entries_49 = "toemail="
        $cfg_entries_50 = "trillian="
        $cfg_entries_51 = "UCBrowser="
        $cfg_entries_52 = "USBSpread="
        $cfg_entries_53 = "vivaldi="
        $cfg_entries_54 = "waterfox="
        $cfg_entries_55 = "WebFilterON="

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x04034b50) and
        (#name >= 4 or #exe >= 2) and 
        10 of ($cfg_section_*)  and
        50 of ($cfg_entries_*) 
} 
