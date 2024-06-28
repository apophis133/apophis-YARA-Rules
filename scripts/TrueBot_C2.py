import base64
import malduck
import re
import json
import argparse
import urllib.parse
from malduck.yara import Yara, YaraString
from smda.Disassembler import Disassembler
from loguru import logger
from typing import Union
from hashlib import sha256
from dataclasses import dataclass


@dataclass
class YaraStringData:
    yara_string: YaraString
    start_va: int
    pos: int
    length: int

    def __init__(self, yara_string, start_va=None, length=None, pos=0):
        self.yara_string = yara_string
        self.start_va = start_va
        self.pos = pos
        self.length = length


class Utils:

    @staticmethod
    def extract_ascii_strings(data, min_len=16):
        chars = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNO" \
                b"PQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"

        string_list = []
        regexp = b'[%s]{%d,}' % (chars, min_len)
        pattern = re.compile(regexp)
        for s in pattern.finditer(data):
            string_list.append(s.group().decode())
        return string_list

    @staticmethod
    def get_yara_offset(yara_string_data: YaraStringData, data: Union[malduck.procmempe, bytes], matching_result=0):

        offset = None

        rule = Yara(name="rule_name", strings={"one_string": yara_string_data.yara_string}, condition="all of them")
        if isinstance(data, malduck.procmempe):
            match = data.yarav(ruleset=rule, addr=yara_string_data.start_va,
                               length=yara_string_data.length, extended=True)
        else:
            match = rule.match(data=data)
        if match:
            for _, v in match.elements["rule_name"].elements.items():
                if isinstance(data, malduck.procmempe):
                    offset = v[matching_result].offset
                else:
                    offset = v[matching_result]
        if offset:
            return offset + yara_string_data.pos
        else:
            return None


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("TrueBot Config Extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Unpacked sample")
    return parser.parse_args()


class TrueBotExtractor:

    def __init__(self, filename):
        self.pe = malduck.procmempe.from_file(filename=filename, image=True)

    def extract_mutex(self, report):
        functions = report.getFunctions()
        for fn in functions:
            for addr, name in fn.apirefs.items():
                if 'kernel32.dll!CreateMutex' in name:
                    logger.debug(f'Found CreateMutex call at {hex(addr)}')
                    variants = None
                    if report.bitness == 32:
                        variants = [YaraStringData(YaraString('4C 8D 05 ?? ?? ?? 00',
                                                              type=YaraString.HEX), addr - 16, 16, 3),
                                    YaraStringData(YaraString('68 ?? ?? ?? ?? (33 | 6A) (DB | 00 | FF)',
                                                              type=YaraString.HEX), addr - 16, 16, 1),
                                    ]
                    elif report.bitness == 64:
                        variants = [YaraStringData(YaraString('4C 8D 05 ?? ?? ?? 00',
                                                              type=YaraString.HEX), addr - 16, 16, 3)
                                    ]
                    offset = None
                    i = 0
                    if variants:
                        while not offset and i < len(variants):
                            try:
                                offset = Utils.get_yara_offset(variants[i], self.pe)
                                i += 1
                            except IndexError:
                                logger.exception("Something went wrong.")
                    mutex = None
                    if offset:
                        logger.debug(f'Found CreateMutex arg push at {hex(offset)}')
                        if report.bitness == 32:
                            o = self.pe.uint32v(addr=offset)
                        elif report.bitness == 64:
                            o = self.pe.uint32v(addr=offset)
                            o = offset + o + 4
                        logger.debug(f'Trying to read Mutex at {hex(o)}')
                        try:
                            mutex = self.pe.utf16z(o)
                        except:
                            mutex = self.pe.asciiz(o)
                    else:
                        logger.error('Unable to find Mutex!')
                    return mutex
        return None

def main():
    args = parse_arguments()
    logger.info(f'Extract {args.file}.')

    tbot_extractor = TrueBotExtractor(filename=args.file)

    with open(args.file, "rb") as fp:
        data = fp.read()
        sha256_hash = sha256(data).hexdigest()

    lazy_b64_pattern = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]'
                                  '[AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$')

    b64_strings = []
    extracted_strings = Utils.extract_ascii_strings(data, min_len=16)

    for s in extracted_strings:
        for a in lazy_b64_pattern.finditer(s):
            tmp = a.group()
            try:
                decoded = base64.b64decode(tmp).decode("utf-8")
                logger.info(f'Found {tmp} string.')
                b64_strings.append(decoded)
            except:
                # ignore all non base64 strings
                pass

    c2 = ''
    rc4_key = ''
    for item in extracted_strings:
        item = item.encode('utf-8')
        for decoded_b64_string in b64_strings:
            decoded = urllib.parse.unquote_to_bytes(decoded_b64_string)
            try:
                decrypted = malduck.rc4(item, decoded)
                if decrypted:
                    decrypted = decrypted.decode('ascii')
                    if c2:
                        if '.php' in decrypted:
                            c2 += decrypted
                            break
                    elif '.' in decrypted:  # lazy check
                        logger.debug(f'Successfully decrypted with key {item}: {decrypted}')
                        c2 += decrypted
                        rc4_key = item
            except:
                pass
    logger.info(f'Successfully extracted C2: {c2}')
    disassembler = Disassembler()
    report = disassembler.disassembleFile(args.file)
    mutex = tbot_extractor.extract_mutex(report)
    config = {'sha256': sha256_hash, 'c2': c2, 'rc4_key_c2': rc4_key.decode('utf-8'),
              'mutex': mutex.decode("utf-8")}
    print(json.dumps(config, indent=1))


if __name__ == "__main__":
    main()
    print(80 * '-' + '\n')
