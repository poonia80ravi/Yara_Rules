import "pe"

rule win_crimsonias_w0 {
    meta:
        author = "@XOR_Hex"
        description = "Detects CrimsonIAS which is a Delphi backdoor that spins up a listener and awaits commands from the operator."
        date = "2020-09-08"
        reference = ""
        hash = "891ece4c40a7bf31f414200c8c2c31192fd159c1316012724f3013bd0ab2a68e"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crimsonias"
        malpedia_version = "20210203"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $command_marker = { 66 99 66 33 }
        $command_code_1 = { 81 ?? 00 66 00 00 }
        $command_code_2 = { 81 ?? 01 11 00 00 }
        $command_code_response_1 = { 01 66 00 00 }
        $command_code_response_2 = { 02 66 00 00 }
        $delphi = "Embarcadero Delphi"
    condition:
        pe.characteristics & pe.DLL
        and $command_marker
        and all of ($command_code_*)
        and all of ($command_code_response_*)
        and $delphi
}
