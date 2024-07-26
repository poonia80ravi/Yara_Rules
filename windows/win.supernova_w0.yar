// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt

rule win_supernova_w0 {
    meta:
        author = "FireEye"
        description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.supernova"
        malpedia_version = "20201216"
        malpedia_license = ""
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""

    strings:
        $dynamic = "DynamicRun"
        $solar = "Solarwinds" nocase
        $string1 = "codes"
        $string2 = "clazz"
        $string3 = "method"
        $string4 = "args"

    condition:
            uint16(0) == 0x5a4d
        and
            uint32(uint32(0x3C)) == 0x00004550
        and
            filesize < 10KB
        and
            3 of ($string*)
        and
            $dynamic
        and
            $solar
}
