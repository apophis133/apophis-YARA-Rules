import base64
import malduck
import os
import re
import urllib
import yara


from smda.Disassembler import Disassembler

from maco import extractor, model
from tempfile import NamedTemporaryFile
from typing import Optional, BinaryIO, List

from scripts.TrueBot_C2 import TrueBotExtractor, Utils

LAZY_B64_PATTERN = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$')

class TrueBot(extractor.Extractor):
    family = "TrueBot"
    author = "@Ap0phis133"
    last_modified = "2024-10-20"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__), '../../YARA-rules/True_Bot.yara')).read()

    def run(self, stream: BinaryIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        result = None
        with NamedTemporaryFile('w+b') as fh:
            data = stream.read()
            fh.write(data)
            fh.flush()

            tbot_extractor = TrueBotExtractor(filename=fh.name)

            b64_strings = []
            extracted_strings = Utils.extract_ascii_strings(data, min_len=16)
            for s in extracted_strings:
                for a in LAZY_B64_PATTERN.finditer(s):
                    tmp = a.group()
                    try:
                        decoded = base64.b64decode(tmp).decode("utf-8")
                        self.logger.info(f'Found {tmp} string.')
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
                                self.logger.debug(f'Successfully decrypted with key {item}: {decrypted}')
                                c2 += decrypted
                                rc4_key = item
                    except:
                        pass
            self.logger.info(f'Successfully extracted C2: {c2}')
            disassembler = Disassembler()
            report = disassembler.disassembleFile(fh.name)
            try:
                mutex = tbot_extractor.extract_mutex(report)
            except Exception as e:
                self.logger.error(f'Unable to extract mutex: {e}')
                mutex = None

            if c2:
                result = model.ExtractorModel(family=self.family)
                result.http.append(result.Http(uri=c2, usage=model.ConnUsageEnum.c2))
                result.encryption.append(model.Encryption(algorithm="RC4", key=rc4_key.decode('utf-8')))
                if mutex:
                    result.mutex.append(mutex.decode("utf-8"))
        return result
