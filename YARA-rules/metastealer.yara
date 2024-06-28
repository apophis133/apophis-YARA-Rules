rule metastealer_dga {
 meta:  
        Description = "This is a simple powerful rule to detect meta stealer"  
        author      = "michelle khalil"  

strings:
    $s1 = "rat\\client\\stealer" ascii wide
    $s2 = "IBrowserBase@stealer" ascii wide
    $s3 = "ChromeBrowser@stealer" ascii wide
    $s4 = "EdgeBrowser@stealer" ascii wide
    $s5 = "FirefoxBrowser@stealer" ascii wide
    $s6 = "stealertest.dll" ascii wide
    $s7 = ".xyz" fullword wide
    $s8 = "hyper-v.exe" fullword wide
condition: 5 of ($s*)

}
