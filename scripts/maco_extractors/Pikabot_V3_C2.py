import os
import yara

from maco import extractor, model
from tempfile import NamedTemporaryFile
from typing import Optional, BinaryIO, List

from scripts.Pikabot_V3_C2 import extract_and_decode, extract_ips

class Pikabot(extractor.Extractor):
    family = "Pikabot"
    author = "@Ap0phis133"
    last_modified = "2024-10-20"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__), '../../YARA-rules/PikaBot_V3_LOADER.yara')).read()

    def run(self, stream: BinaryIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        result = None
        with NamedTemporaryFile('w+b') as fh:
            fh.write(stream.read())
            fh.flush()

            # Get decoded data from a certain start and end point
            decoded_data = extract_and_decode(fh.name, 0x0E560, 0x0EB60)

        # Extract IPs from decoded data
        ips = extract_ips(decoded_data)
        if ips:
            # Instantiate instance of MACO model
            result = model.ExtractorModel(family=self.family, version="3")
            for ip in ips:
                # Add C2 IPs to report
                result.http.append(result.Http(hostname=ip, usage=model.ConnUsageEnum.c2))

        return result
