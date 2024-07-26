rule win_darkrat_w0 {
    meta:
        author = "Albert Zsigovits"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkrat"
        malpedia_version = "20191012"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
            
    strings:
	    $pdb = "C:\\Users\\darkspider" ascii wide
	    $cmd = "cmd.exe /C ping 127.0.0.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"" ascii wide

	    $guid1 = "SOFTWARE\\Microsoft\\Cryptography" ascii wide
	    $guid2 = "MachineGuid" ascii wide

	    $persi1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
	    $persi2 = "WinSystem32" ascii wide

	    $bin = "pastebin.com/raw/" ascii wide
	    $import0 = "NtUnmapViewOfSection" ascii wide
	    $import1 = "WriteProcessMemory" ascii wide
	    $import2 = "ResumeThread" ascii wide
	    $import3 = "GetNativeSystemInfo" ascii wide
	    $import4 = "URLOpenBlockingStream" ascii wide
	    $import5 = "VirtualFree" ascii wide
	    $import6 = "VirtualAlloc" ascii wide
	    $import7 = "GetModuleHandle" ascii wide
	    $import8 = "LoadLibrary" ascii wide
	    $import9 = "CreateMutex" ascii wide

	    $vbs0 = "Set objShell = WScript.CreateObject(\"WScript.Shell\")" ascii wide
	    $vbs1 = "Set objWMIService = GetObject(\"winmgmts:\\\\\" & sComputerName & \"\\root\\cimv2\")" ascii wide
	    $vbs2 = "Set objItems = objWMIService.ExecQuery(sQuery)" ascii wide
	    $vbs3 = "sQuery = \"SELECT * FROM Win32_Process\"" ascii wide
	    $vbs4 = "wscript.exe" ascii wide

	    $net0 = "POST" ascii wide
	    $net1 = "&taskid=" ascii wide
	    $net2 = "&taskstatus=" ascii wide
	    $net3 = "&spreadtag=" ascii wide
	    $net4 = "&operingsystem=" ascii wide
	    $net5 = "&arch=" ascii wide
	    $net6 = "&cpuName=" ascii wide
	    $net7 = "&gpuName=" ascii wide
	    $net8 = "&botversion=" ascii wide
	    $net9 = "&antivirus=" ascii wide
	    $net10 = "&netFramework4=" ascii wide
	    $net11 = "&netFramework35=" ascii wide
	    $net12 = "&netFramework3=" ascii wide
	    $net13 = "&netFramework2=" ascii wide
	    $net14 = "&installedRam=" ascii wide
	    $net15 = "&aornot=" ascii wide
	    $net16 = "&computername=" ascii wide
	    $net17 = "hwid=" ascii wide
	    $net18 = "request=" ascii wide

    condition:
	    $pdb or $cmd or ( all of ($guid*) and all of ($persi*) ) or ( 3 of ($vbs*) ) or ( all of ($import*) and $bin ) or ( all of ($net*) )
}
