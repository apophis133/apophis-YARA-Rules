rule MAL_EXE_Prysmax_STEALER : EXE STEALER {
   meta:
      description = "This rule detects Prysmax malware samples."
      author      = "Michelle Khalil"
      sharing     = "TLP:CLEAR"
      tags        = "windows,exe,stealer"
      os          = "windows"
      category    = "Malware"
strings:
        $a1 = "TEMPPrysmax" ascii fullword wide
        $a2 = "Prysmax/Apps" ascii fullword wide
        $a3 = "Prysmax/Wallets" ascii fullword wide
        $a4 = "Prysmax_Cookies_ " ascii fullword wide
        $a5 = "Prysmax.zip" ascii fullword wide
        $a6 = "nprysmax.xyz stealer <3\nNombre: " ascii fullword wide
        $a7 = "nprysmax.xyz stealer <3\nURL: " ascii fullword wide
        $a8 = "nprysmax.xyz stealer <3\nName: " ascii fullword wide
        $s1 = "\\nExtraction completed!\\n" ascii fullword wide
        $s2 = "\\n=== Iniciando proceso de compresión ===\\n" ascii fullword wide
        $s3 = "Archivo ZIP creado correctamente\\n" ascii fullword wide
        $s4 = "\\n=== Preparando envío al servidor ===\\n" ascii fullword wide
        $s5 = "temp_cards_" ascii fullword wide
        $s6 = "temp_history_" ascii fullword wide
        $s7 = "Task join error: " ascii fullword wide
        $s8 = "Directorio temporal: " ascii fullword wide
        $s9 = "Total cookies collected: " ascii fullword wide
        $s10 = "Error processing browser: " ascii fullword wide
        $s11 = "\\nUsername: " ascii fullword wide
        $s12 = "\\nPassword: " ascii fullword wide
        $s13 = "_cards.txt" ascii fullword wide
        $s14 = "_history.txt" ascii fullword wide
        $s15 = "_passwords.txt" ascii fullword wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($a*)) or
        13 of them
}
