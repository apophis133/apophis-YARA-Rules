import re

def extract_and_decode(file_path, start, end):
    """
    This function extracts and decodes a byte range from a file as UTF-8.

    Args:
        file_path: Path to the file.
        start: Byte offset to start reading from.
        end: Byte offset to stop reading at (exclusive).

    Returns:
        The decoded data as a string (may contain errors if invalid UTF-8).
    """
    with open(file_path, 'rb') as f:
        f.seek(start)
        data = f.read(end - start)
    decoded_data = data.decode('utf-8', errors='ignore')
    # Strip null bytes from decoded data
    return decoded_data.replace('\x00', '')

def extract_ips(decoded_data):
    """
    This function extracts IP addresses from a decoded string using a regular expression.

    Args:
        decoded_data: The decoded string from the file.

    Returns:
        A list of extracted IP addresses (empty list if none found).
    """
    # Regex pattern for IPv4 addresses with word boundaries
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    matches = re.finditer(ip_pattern, decoded_data)
    ips = [match.group() for match in matches]
    return ips

if __name__ == "__main__":
    # Usage example
    file_path = 'ffa6a6b56c154ed6ae3de4b31ee05bd5c1e8161954fe79ffc9f6dc8408d24659'
    start = 0x0E560
    end = 0x0EB60

    decoded_data = extract_and_decode(file_path, start, end)

    # Print decoded data to verify (optional)
    print("Decoded Data:")
    print(decoded_data)

    # Extract IPs
    ips = extract_ips(decoded_data)

    if ips:
        # Print extracted IPs
        print("Extracted IPs:")
        for ip in ips:
            print(f'{ip}\n')
    else:
        print("No IPs found.")
