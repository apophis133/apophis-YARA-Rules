rule Detects_WinDefender_AntiEmaulation {
    meta:
        author = "michelle khalil"
        description = "Detects malwares that checks for WinDefender anti-emulation techniques"
    strings:
        $s1 = "JohnDoe" fullword ascii wide
        $s2 = "HAL9TH" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
