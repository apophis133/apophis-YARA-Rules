import os
import re
import yara

from maco import extractor, model
from typing import Optional, BinaryIO, List

from scripts.metastealer_decrypt_strings import decrypt_data

class MetaStealer(extractor.Extractor):
    family = "MetaStealer"
    author = "@Ap0phis133"
    last_modified = "2024-10-20"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__), '../../YARA-rules/Meta_STEALER.yara')).read()

    def run(self, stream: BinaryIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        decrypted_strings = []
        file_content = stream.read()

        string_egg = rb'\x66[\x00-\x0f]\xef'

        # Find offsets of the string egg in the file content
        offsets = [m.start() for m in re.finditer(string_egg, file_content, re.DOTALL)]

        prev_offset = 0
        for offset in offsets:
            # Extract data preceding the current offset
            test_data = file_content[prev_offset:offset]

            # Find values matching the pattern
            vals = re.findall(b'''\xc7\x85..\xff\xff....''', test_data)
            if vals:
                # Extract the last 8 matching values
                last_8_vals = vals[-8:]
            else:
                last_8_vals = []

            try:
                decrypted_data = decrypt_data(last_8_vals)

                # Decrypt the data
                for i in range(len(decrypted_data)):
                    decrypted_data[i] ^= decrypted_data[i + 4]

                # Remove null bytes and decode the ASCII string
                decrypted_str = decrypted_data.replace(b'\x00', b'').decode('ascii')

                # Print the decrypted string
                self.logger.info(f'Decrypted String: {decrypted_str}')
            except IndexError:
                pass
            except Exception as e:
                self.logger.error(e)

            prev_offset = offset

        if decrypted_strings:
            return model.ExtractorModel(family=self.family, decoded_strings=decrypted_strings)
