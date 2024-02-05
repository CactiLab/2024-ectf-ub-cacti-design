import argparse
from pathlib import Path
import sys

def read_binary_file(path):
    with open(path, 'rb') as file:
        return file.read()

def format_key_for_c_define(key):
    return ', '.join(f'0x{byte:02x}' for byte in key)

def parse_and_modify_header(header_path, priv_key, pub_key):
    with open(header_path, 'r') as file:
        lines = file.readlines()

    ap_pin, ap_token = None, None
    for line in lines:
        if '#define AP_PIN' in line:
            ap_pin = line.split('"')[1]
        elif '#define AP_TOKEN' in line:
            ap_token = line.split('"')[1]

    with open(header_path, 'w') as file:
        for line in lines:
            if line.strip().startswith('#define AP_PIN') or line.strip().startswith('#define AP_TOKEN'):
                file.write(line)
            else:
                if not line.strip() or line.strip().startswith('#'):
                    file.write(line)
                else:
                    break  # Stop before non-directive, non-empty lines
        file.write(f'#define PRIVATE_KEY {format_key_for_c_define(priv_key)}\n')
        file.write(f'#define PUBLIC_KEY {format_key_for_c_define(pub_key)}\n')
    
    return ap_pin, ap_token

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--priv-key-file", type=Path, required=True)
    parser.add_argument("--pub-key-file", type=Path, required=True)
    args = parser.parse_args()
    
    if not args.header_file.exists():
        print(f"Header file {args.header_file} does not exist. Build the deployment package first.")
        sys.exit(1)
    
    if not args.priv_key_file.exists():
        print(f"Private key file {args.priv_key_file} does not exist.")
        sys.exit(1)
    
    if not args.pub_key_file.exists():
        print(f"Public key file {args.pub_key_file} does not exist.")
        sys.exit(1)
    
    priv_key = args.priv_key_file.read_bytes()
    pub_key = args.pub_key_file.read_bytes()
    
    ap_pin, ap_token = parse_and_modify_header(args.header_file, priv_key, pub_key)
    
    if ap_pin and ap_token:
        print(f"AP_PIN: {ap_pin}")
        print(f"AP_TOKEN: {ap_token}")
    else:
        print("Failed to find AP_PIN or AP_TOKEN in the header file.")

if __name__ == "__main__":
    main()
