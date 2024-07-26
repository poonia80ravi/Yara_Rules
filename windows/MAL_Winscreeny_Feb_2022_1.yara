rule MAL_Winscreeny_Feb_2022_1 : Winscreeny Backdoor
{
   meta:
        description = "Detect the Winscreeny inplant against Iranian infrastructures"
        author = "Arkbird_SOLG"
        reference = "https://research.checkpoint.com/2022/evilplayout-attack-against-irans-state-broadcaster/"
        date = "2022-02-17"
        hash1 = "41e0c19cd6a66b4c48cc693fd4be96733bc8ccbe91f7d92031d08ed7ff69759a"
        hash2 = "e9e4a8650094e4de6e5d748f7bc6f605c23090d076338f437a9a70ced4a9382d"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 02 8e 69 ?? 12 ?? 28 ?? 00 00 0a 28 13 00 00 06 [0-1] 02 8e [2-8] 00 00 00 02 16 9a 28 13 00 00 06 [0-1] 02 16 9a 72 ?? 01 00 70 28 ?? 00 00 0a }
        $s2 = { 03 6f ?? 00 00 0a 0a 06 15 15 15 28 ?? 00 00 06 0b 72 ?? ?? 00 70 0c 07 72 ?? 05 00 70 6f ?? 00 00 0a 72 ?? 05 00 70 28 ?? 00 00 0a }
        $s3 = { 03 16 32 09 02 03 73 ?? 00 00 06 2b 01 02 0a 73 ?? 00 00 0a 0b 06 12 02 12 03 28 ?? 00 00 06 }
        $s4 = { 02 03 28 ?? 00 00 06 0a 02 06 12 01 28 ?? 00 00 06 0c 02 03 08 07 28 ?? 00 00 06 }
        $s5 = { 00 70 0a 72 ?? ?? 00 70 0b [0-1] 72 ?? 01 00 70 73 ?? 00 00 0a [1-2] 16 6f ?? 00 00 0a [1-2] 17 6f ?? 00 00 0a }
    condition:
        uint16(0) == 0x5A4D and filesize > 10KB and all of ($s*) 
}
