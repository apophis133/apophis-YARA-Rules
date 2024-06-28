rule true_bot {
 meta:  
        author      = "michelle khalil"
        Description = "This is a simple powerful rule to detect true_bot"   
    strings:
        $c2_params_1        = "n=%s&o=%s&a=%d&u=%s&p=%s&d=%s" fullword
        $c2_params_2        = "n=%s&l=%s"   fullword 
        $c2_id              = "%08x-%08x"   fullword
        $cmd_commands_1     = "LSEL" ascii 
        $cmd_commands_2     = "TFOUN" ascii 
        $cmd_commands_3     = "EFE" ascii 
        $cmd_commands_4     = "S66" ascii 
        $cmd_commands_5     = "Z66" ascii
        $random_exe         = "%s\\Intel\\RuntimeBroker.exe" fullword wide
        $pipe_word          = "\\\\.\\Pipe\\Scrooling%d" fullword wide
        $random_file        = "\\\\..\\\\.filem.film.AVIVIV" fullword wide
   condition: all of them
}
