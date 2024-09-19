rule AntiVM {
    meta:
        author = "Michelle khalil"
        description = "Detects malwares use anti-VM checks"
    strings:
        $s1 = "windanr.exe" fullword ascii wide
        $s2 = "vboxservice.exe" fullword ascii wide
        $s3 = "vboxtray.exe" fullword ascii wide
        $s4 = "vmtoolsd.exe" fullword ascii wide
        $s5 = "vmware" fullword ascii wide
        $s6 = "vbox" fullword ascii wide
        $s7 = "vmci.s" fullword ascii wide
        $s8 = "vmmemc" fullword ascii wide
        $s9 = "qemu-ga.exe" fullword ascii wide
        $s10 = "qga.exe" fullword ascii wide
        $s11 = "prl_tools.exe" fullword ascii wide
        $s12 = "qemu" fullword ascii wide
        $s13 = "virtio" fullword ascii wide
    condition:
         uint16(0) == 0x5a4d and 8 of them
}
