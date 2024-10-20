import re

def decrypt_data(data):
    decrypted_data = bytearray()
    for i in range(8):
        decrypted_data.extend(data[i][-4:])
    return decrypted_data

if __name__ == "__main__":
    file_path = r'C:\Users\MaldevUser\Desktop\84B890ED75D0D50D/metastealer.exe'

    with open(file_path, 'rb') as file:
        file_content = file.read()

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
            print(f'Decrypted String: {decrypted_str}')
        except IndexError:
            pass
        except Exception as e:
            print(f'Error: {e}')

        prev_offset = offset
