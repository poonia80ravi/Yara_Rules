rule win_electricfish_w0 {   
      meta:   
          author = "AlienVault Labs"   
          type = "malware"   
          description = "HiddenCobraElectricFish"   
          copyright = "Alienvault Inc. 2019"   
          reference = "a3a1a43f0e631c10ab42e5404b61580e760e7d6f849ab8eb5848057a8c60cda2,7efe8a7ad9c6a6146bddd5aef9ceba477ca6973203a41f4b7f823095a90cb10f"   
          malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.electricfish"
          malpedia_version = "20190815"
          malpedia_license = "CC BY-NC-SA 4.0"
          malpedia_sharing = "TLP:WHITE"
      strings:   
          $x1 = "CCGC_LOG ===>"   
          $x2 = "<==RECV==="   
          $x3 = "aaaabbbbccccdddd"   
      condition:   
           uint16(0) == 0x5a4d and all of them   
}
