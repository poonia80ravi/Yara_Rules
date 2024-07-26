import "pe"
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2019-08-07
   Identifier: APT41
   Reference: https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html
   License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule win_highnoon_bin_w0 {
    meta:
        description = "Detects APT41 malware HIGHNOON.BIN"
        author = "Florian Roth"
        reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
        date = "2019-08-07"
        score = 90
        hash = "490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994"
        hash = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.highnoon_bin"
        malpedia_version = "20190812"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "PlusDll.dll" fullword ascii
        $s2 = "\\Device\\PORTLESS_DeviceName" fullword wide
        $s3 = "%s%s\\Security" fullword ascii
        $s4 = "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
        $s5 = "%s%s\\Enum" fullword ascii
    condition:
        pe.imphash() == "b70358b00dd0138566ac940d0da26a03" or 3 of them
}
