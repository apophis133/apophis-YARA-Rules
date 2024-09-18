rule MAL_EXE_Exhaust_RAT_Sep_15 : EXE RAT {
   meta:
      description = "This rule detects Exhaust RAT malware samples."
      author      = "Michelle Khalil"
      date        = "2024-09-15"
      sharing     = "TLP:CLEAR"
      tags        = "windows,exe,rat"
      sample      = "6fe842c8f4255dd8f2dc1277e1665d7ef18a7429722aca1bd667cfc62bf2ed07"
      reference   = "https://x.com/MalGamy12/status/1811360391001227636"
      os          = "windows"
      category    = "Malware"
   strings:
      $x1 = "Exhaust-RAT.pdb" fullword ascii
      $s1 = "System32\\drivers\\vioinput.sys" fullword wide 
      $s2 = "HKLM\\SYSTEM\\ControlSet001\\Services\\xenevtchn" fullword ascii 
      $s3 = "c:\\windows\\system32\\drivers\\prlvideo.sys" fullword ascii 
      $s4 = "xenservice.exe" fullword wide 
      $s5 = "vboxtray.exe" fullword wide  
      $s6 = "C:\\windows\\System32\\vboxhook.dll" fullword wide 
      $s7 = "prl_cc.exe" fullword wide 
      $s8 = ".data$rs" fullword ascii 
      $s9 = "joeboxserver.exe" fullword wide 
      $s10 = "SYSTEM\\ControlSet001\\Services\\BalloonService" fullword wide 
      $s11 = "avghooka.dll" fullword ascii 
      $s12 = "nqemu-ga.exe" fullword wide 
      $s13 = "System32\\drivers\\pvpanic.sys" fullword wide 
      condition:
      uint16(0) == 0x5a4d 
      and 8 of ($s*) and $x1
}
