rule APT_Turla_SilentMoon_sep_22 : EXE MALWARE {
   meta:
      description = "This rule detects SilentMoon malware samples." 
      author      = "Michelle Khalil"
      date        = "2024-09-22"
      sharing     = "TLP:CLEAR"
      tags        = "windows,exe"
      sample      = "94421ccb97b784c43d92c4b1438481eee9c907db6b13f6cfc4b86a6bb057ddcd"
      os          = "windows"
      category    = "Malware"      
   strings:
      $s1 = "%d blocks, %d sorted, %d scanned" ascii fullword
      $s2 = "REMOTE_NS:ERROR:%d" ascii fullword 
      $s3 = { 5c 5c 25 73 5c 70 69 70 65 5c 25 73 }
      $s4 = { 5c 00 69 00 6e 00 66 00 5c 00 00 00 [4-16] 2e 00 69 00 6e 00 66 }    
      $s5 = { 5c 5c 25 73 5c 69 70 63 24 }
   condition:
      uint16(0) == 0x5a4d and
      filesize > 20KB and
      all of them
}
