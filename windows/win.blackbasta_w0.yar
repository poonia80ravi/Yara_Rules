rule win_blackbasta_w0 {
   meta:
      description = "Black Basta is a new ransomware strain discovered during April 2022 - looks in dev since at least early February 2022 - and due to their ability to quickly amass new victims and the style of their negotiations, this is likely not a new operation but rather a rebrand of a previous top-tier ransomware gang that brought along their affiliates."
      author = "rcoliveira@protonmail.com"
      reference_1 = "https://securelist.com/luna-black-basta-ransomware/106950/"
      reference_2 = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbasta"
      hash_1 = "96339a7e87ffce6ced247feb9b4cb7c05b83ca315976a9522155bad726b8e5be"
      hash_2 = "0d6c3de5aebbbe85939d7588150edf7b7bdc712fceb6a83d79e65b6f79bfc2ef"
      date = "2022-07-21"
      sharing = "TLP:WHITE"
      malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbasta"
      malpedia_version = "20220722"
      malpedia_license = "CC BY-NC-SA 4.0"
      malpedia_sharing = "TLP:WHITE"
   strings:
      $s1 = "aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion" fullword ascii
      $s2 = "Your data are stolen and encrypted" fullword ascii
      $s3 = "The data will be published on TOR website if you do not pay the ransom" fullword ascii
      $s4 = "Input is not valid base64-encoded data." fullword ascii
      $s5 = "(you should download and install TOR browser first https://torproject.org)" fullword ascii
      $a1 = "_Z12EncryptBytesP8Chacha20PhS1_S1_i" fullword ascii
      $a2 = "_Z21GetEncryptedNextBlockP8Chacha20PN3ghc10filesystem13basic_fstreamIcSt11char_traitsIcEEEPhS8_ixS8_" fullword ascii /* score: '17.00'*/
      $a3 = "_ZNSt10_HashtableISsSt4pairIKSsPcESaIS3_ENSt8__detail10_Select1stESt8equal_toISsESt4hashISsENS5_18_Mod_range_hashingENS5_20_Default_ranged_hashENS5_20_Prime_rehash_policyENS5_17_Hashtable_traitsILb1ELb0ELb1EEEE21_M_insert_unique_nodeEmmPNS5_10_Hash_nodeIS3_Lb1EEE" fullword ascii
      $a4 = "_ZNSt8__detail9_Map_baseISsSt4pairIKSsPcESaIS4_ENS_10_Select1stESt8equal_toISsESt4hashISsENS_18_Mod_range_hashingENS_20_Default_ranged_hashENS_20_Prime_rehash_policyENS_17_Hashtable_traitsILb1ELb0ELb1EEELb1EEixEOSs" fullword ascii
      $a5 = "_ZN3ghc10filesystem4path28postprocess_path_with_formatENS1_6formatE" fullword ascii
      $a6 = "C:/Users/dssd/Desktop/src" fullword ascii
      $a7 = "totalBytesEncrypted" fullword ascii
   condition:
      filesize < 600KB and
      (1 of ($s*) and 1 of ($a*) ) or (8 of them)
}
