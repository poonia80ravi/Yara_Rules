rule win_grandsteal_w0 {
    meta: 
        author = "p3pperp0tts"
        source = "http://www.peppermalware.com/2019/03/analysis-of-net-stealer-grandsteal-2019.html"
        description = "yara rule for grandsteal"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grandsteal"
        malpedia_version = "20200129"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $s1 = "ws://{0}:{1}/websocket" wide
        $s2 = "GrabBrowserCredentials: " wide
        $s3 = "GrabColdWallets: " wide
        $s4 = "GrabDesktopFiles: " wide
        $s5 = "GrabTelegram: " wide
        $s6 = "ColdWallets parser has been started" wide
        $s7 = "DiscordSession parser has been started" wide
        $s8 = "Rdps parser has been started" wide
        $s9 = "DesktopFiles parser has been started" wide
        $s10 = "FTPs parser has been started" wide
        $s11 = "TelegramSession parser has been started" wide
        $s12 = "ListOfProcesses parser has been started" wide
        $s13 = "ListOfPrograms parser has been started" wide
        $s14 = "card_number_encrypted" wide
        $s15 = "\\Litecoin\\wallet.dat" wide
        $s16 = "\\Bitcoin\\wallet.dat" wide
        $s17 = "\\Exodus\\exodus.wallet" wide
        $s18 = "\\Electrum\\wallets" wide
        $s19 = "\\Ethereum\\wallets" wide
        $s20 = "monero-project" wide
        $s21 = "Discord dump UNKNOWN" wide
        $s22 = "{0}\\FileZilla\\recentservers.xml" wide
        $s23 = "{0}\\FileZilla\\sitemanager.xml" wide
        $s24 = "cookies.sqlite" wide
        $s25 = "password-check" wide
        $s26 = "AppData\\Roaming\\Telegram Desktop\\tdata\\D877F783D5D3EF8C" wide
        $s27 = "%USERPROFILE%\\AppData\\Local\\Temp\\Remove.bat" wide
        $s28 = "taskkill /F /PID %1" wide
        $s29 = "choice /C Y /N /D Y /T 3 & Del %2" wide
        $s30 = "ExtractPrivateKey" wide
        $s31 = "formSubmitURL" wide
        $s32 = "passwordField" wide
        $s33 = "usernameField" wide
        $s34 = "GrabDiscord" wide
        $s35 = "encryptedPassword" wide
        $s36 = "masterPassword" wide
        $s37 = "WalletName" wide
    condition:
        (30 of them)
}
