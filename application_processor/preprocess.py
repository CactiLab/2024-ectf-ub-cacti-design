import argparse
from pathlib import Path
import sys

def read_binary_file(path):
    with open(path, 'rb') as file:
        return file.read()

def format_key_for_c_define(key):
    return ', '.join(f'0x{byte:02x}' for byte in key)

def parse_and_modify_header(header_path, ap_priv_key, cp_pub_key):
    with open(header_path, 'r') as file:
        lines = file.readlines()

    cp_ids, cp_cnt, ap_pin, ap_token = None, None, None, None
    for line in lines:
        if '#define AP_PIN' in line:
            ap_pin = line.split('"')[1]
        elif '#define AP_TOKEN' in line:
            ap_token = line.split('"')[1]
        elif '#define COMPONENT_IDS' in line:
            cp_ids = line.strip().split('COMPONENT_IDS ')[1]
        elif '#define COMPONENT_CNT' in line:
            cp_cnt = line.strip().split('COMPONENT_CNT ')[1]

    with open(header_path, 'w') as file:
        for line in lines:
            if line.strip().startswith('#define AP_PIN') or line.strip().startswith('#define AP_TOKEN'):
                file.write(line)
            else:
                if not line.strip() or line.strip().startswith('#'):
                    file.write(line)
                else:
                    break  # Stop before non-directive, non-empty lines
        file.write(f'#define AP_PRIVATE_KEY {format_key_for_c_define(ap_priv_key)}\n')
        file.write(f'#define CP_PUBLIC_KEY {format_key_for_c_define(cp_pub_key)}\n')
    
    return cp_ids, cp_cnt, ap_pin, ap_token

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--ap-priv-key-file", type=Path, required=True)
    parser.add_argument("--cp-pub-key-file", type=Path, required=True)
    args = parser.parse_args()
    
    if not args.header_file.exists():
        print(f"Header file {args.header_file} does not exist.")
        sys.exit(1)
    
    if not args.ap_priv_key_file.exists():
        print(f"AP's private key file {args.ap_priv_key_file} does not exist. Build the deployment package first.")
        sys.exit(1)
    
    if not args.cp_pub_key_file.exists():
        print(f"CP's public key file {args.cp_pub_key_file} does not exist. Build the deployment package first.")
        sys.exit(1)
    
    priv_key = args.ap_priv_key_file.read_bytes()
    pub_key = args.cp_pub_key_file.read_bytes()
    
    cp_ids, cp_cnt, ap_pin, ap_token = parse_and_modify_header(args.header_file, priv_key, pub_key)
    
    if ap_pin and ap_token and cp_ids and cp_cnt:
        print(f"AP_PIN: {ap_pin}")
        print(f"AP_TOKEN: {ap_token}")
        print(f"COMPONENT_IDS: {cp_ids}")
        print(f"COMPONENT_CNT: {cp_cnt}")
    else:
        print("Error: Could not find AP_PIN, AP_TOKEN, COMPONENT_IDS, or COMPONENT_CNT in header file.")

if __name__ == "__main__":
    main()
