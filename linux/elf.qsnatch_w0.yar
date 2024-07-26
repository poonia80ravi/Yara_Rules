/*
    based on these samples:
      - 09ab3031796bea1b8b79fcfd2b86dac8f38b1f95f0fce6bd2590361f6dcd6764
      - 5cb5dce0a1e03fc4d3ffc831e4a356bce80e928423b374fc80ee997e7c62d3f8
      - 8fd16e639f99cdaa7a2b730fc9af34a203c41fb353eaa250a536a09caf78253b
      - 9526ccdeb9bf7cfd9b34d290bdb49ab6a6acefc17bff0e85d9ebb46cca8b9dc2
      - 3c38e7bb004b000bd90ad94446437096f46140292a138bfc9f7e44dc136bac8d
      - 5130282cdb4e371b5b9257e6c992fb7c11243b2511a6d4185eafc0faa0e0a3a6
      - 15892206207fdef1a60af17684ea18bcaa5434a1c7bdca55f460bb69abec0bdc
*/
rule elf_qsnatch_w0 {
    meta:
        author = "Johannes Bader mail@johannesbader.ch"
        date = "2019-11-13"
        description = "Detects QSnatch shell scripts"
        
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.qsnatch"
        malpedia_version = "20191113"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $shebang = "#!/bin/sh"

        $pat_url = "https://${host}.${ext}/qnap_firmware.xml?t=$(date +%s)"
        $pat_public_key = "DNnpDGbq632Bs8ESd3ueHk9OY/UZxWeN3UdbseFxK35XAgMBAAE="
        $pat_decrypt_key = "7C0vK4SzMO15zBxLD7XCi5hbjgP1ZjkJ"

    condition:
        $shebang at 0 
        and any of ($pat_*) 
        and filesize < 200KB

}
