rule win_frat_w0 {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://twitter.com/jeFF0Falltrades/status/1270709679375646720"
    source = "https://github.com/jeFF0Falltrades/IoCs/blob/master/Broadbased/frat.md"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.frat"
    malpedia_rule_date = "20200612"
    malpedia_version = "20200612"
    malpedia_license = "CC BY-NC-SA 4.0"
    malpedia_sharing = "TLP:WHITE"

  strings:
    $str_path_0 = "FRat\\\\Short-Port" wide ascii
    $str_path_1 = "FRatv8\\\\Door\\\\Stub" wide ascii 
    $str_path_2 = "snapshot\\\\Stub\\\\V1.js" wide ascii 
    $str_sails = "sails.io" wide ascii 
    $str_crypto = "CRYPTOGAMS by <appro@openssl.org>" wide ascii 
    $str_socketio = "socket.io-client" wide ascii 

  condition:
    3 of them
}
