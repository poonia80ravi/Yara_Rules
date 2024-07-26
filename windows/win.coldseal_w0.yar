rule win_coldseal_w0 {
	meta:
		author = "mho <info@mha.bka.de>"
		description = "High amount of delimiter strings, show that this file contains a payload encrypted using Cold$eal Project. This will hit on a lot of ransomware like Cerber, Locky, GandCrab."
        note = "Usually the files are compressed with upx or pecompact when found in the wild. This rule will only work on decompressed samples or using virustotal.com retrohunt."
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coldseal"
        malpedia_rule_date = "20201127"
        malpedia_hash = ""
        malpedia_version = "20201127"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

	strings:
		$delim01 = {23 23 24 2A 2D 2A 2E 3B 2E 3F}
		$delim02 = {16 89 AB A7 F2 C1 19 17 28 EC}
		$delim03 = {32 44 21 AF 7C 3F CA E5 21 69}
		$delim04 = "*)#/&*"
		$delim05 = "/)#**&"
		$delim06 = {F1 E9 AF 29 4B}
		$delim07 = {1C 56 7D 3C 64 1E 46 55 64}
		$delim08 = {A5 65 BC 92 2C}
		$delim09 = ")#&**/"
		$delim10 = "*#/*)&"
		$delim11 = {2C 59 22 CB 92 CB 92 92 2C BC A5 C6 BC A5 65 CA 56 52 A5 65}
		$delim12 = {2A 23 22 A2 A2 F2 FA 2D 62}
		$delim13 = {2A 59 22 CB 92 CB 92 92 2C BC A5 C6 BC A5 65 CA 56 52 A5 12}
		$delim14 = {13 59 22 CB 92 CB 92 92 2C BC A5 C6 BC A5 65 CA 56 52 A5 31}
		$delim15 = {46 59 22 CB 92 CB 92 92 2C BC A5 C6 BC A5 65 CA 56 52 A5 64}
		$delim16 = {85 59 22 CB 92 CB 92 92 2C BC A5 C6 BC A5 65 CA 56 52 A5 58}
		$delim17 = {77 59 22 CB 92 CB 92 92 2C BC A5 C6 BC A5 65 CA 56 52 A5 77}
		$delim18 = {12 56 9F E4 98 A8 98 65 AF C5}
		$delim19 = {4A 8E D7 1C D0 E0 D0 9D E7 FD}
                $delim20 = {46 59 22 CB 92 CB 92 92 2C BC A5 C6 BC A5 65 CA 56 52 A5 64}
	condition:
		for any of ($delim*) : (# > 6)
}
