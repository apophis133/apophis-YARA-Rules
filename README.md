# YARA Rules and Scripts

Hello! This repository contains a set of my detection rules to improve detection and hunting visibility and context. Where applicable, YARA has its description with the name and the variant of the malware family.

## YARA Rules

The `YARA-rules` directory contains the following YARA rules :
- **Detects_WinDefender_AntiEmulator.yara** - Detects specific anti-emulation techniques against the Windows Defender.
- **Detects_anti-VM_checks.yara** - Identifies anti-virtual machine checks.
- **PikaBot_V3.yara** - Detection rules for the PikaBot version 3 malware.
- **TrueBot.yara** - Detection rules for the TrueBot malware.
- **metastealer.yara** - Detection rules for Metastealer malware.

## Scripts

The `scripts` directory contains the following scripts :

- **Pikabot_V3_C2.py** - Configuration extractor for PikaBot version 3.
- **TrueBot_C2.py** - Configuration extractor for TrueBot.
- **metastealer_decrypt_strings.py** - Decryption script for Metastealer malware.

These scripts are designed to extract configuration and decrypt strings from malware samples that the YARA rules detect.

## Contact

If you have any questions or need further information, you can contact me at:

- **LinkedIn**: [Apophis133](https://www.linkedin.com/in/apophis133)
- **Blog**: [Apophis133 on Medium](https://apophis133.medium.com)
- **Twitter**: [@Ap0phis133](https://x.com/Ap0phis133)
