rule SUSP_BAT_OBFUSC_Jul24_2 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Michelle khalil"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
   strings:
      $s1 = "%vdpyogfxzy%"
      $s2 = "%%vdpyoiikiv%"
      $s3 = "%dvorqnsonq%"
      $s4 = "%dvorqnsonq%"
      $s5 = "%eouvhvwtcd%"
      $s6 = "%eouvhpftvr%"
      $s7 = "%edctifpkaa%"
      $s8 = "%edctikqgaz%"
      $s9 = "%pcrkixcbjt%"
      $s10 = "%pcrkiixyfg%"
      $s11 = "%fkfuddizim%"
      $s12 = "%fkfudyavci%"
      $s13 = "%ufwckpxztg%"
      $s14 = "%ufwckjwfuj%"
      $s15 = "%epbubsphjs%"
      $s16 = "%epbubacyuq%"
   condition:
   filesize < 300KB and
      2 of them 
}
