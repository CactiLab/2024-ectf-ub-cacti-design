import argparse
from pathlib import Path
import sys

def read_binary_file(path):
    with open(path, 'rb') as file:
        return file.read()

def format_key_for_c_define(key):
    return ', '.join(f'0x{byte:02x}' for byte in key)

def parse_and_modify_header(header_path, cp_priv_key, ap_pub_key):
    with open(header_path, 'r') as file:
        lines = file.readlines()

    cp_id, att_loc, att_date, att_customer = None, None, None, None
    for line in lines:
        if '#define COMPONENT_ID' in line:
            cp_id = line.strip().split('COMPONENT_ID ')[1]
        elif '#define ATTESTATION_LOC' in line:
            att_loc = line.split('"')[1]
        elif '#define ATTESTATION_DATE' in line:
            att_date = line.split('"')[1]
        elif '#define ATTESTATION_CUSTOMER' in line:
            att_customer = line.split('"')[1]

    with open(header_path, 'w') as file:
        for line in lines:
            if not line.strip() or line.strip().startswith('#'):
                file.write(line)
            else:
                break  # Stop before non-directive, non-empty lines
        file.write(f'#define CP_PRIVATE_KEY {format_key_for_c_define(cp_priv_key)}\n')
        file.write(f'#define AP_PUBLIC_KEY {format_key_for_c_define(ap_pub_key)}\n')
    
    return cp_id, att_loc, att_date, att_customer

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--cp-priv-key-file", type=Path, required=True)
    parser.add_argument("--ap-pub-key-file", type=Path, required=True)
    args = parser.parse_args()
    
    if not args.header_file.exists():
        print(f"Header file {args.header_file} does not exist.")
        sys.exit(1)
    
    if not args.cp_priv_key_file.exists():
        print(f"CP's private key file {args.cp_priv_key_file} does not exist. Build the deployment package first.")
        sys.exit(1)
    
    if not args.ap_pub_key_file.exists():
        print(f"AP's public key file {args.ap_pub_key_file} does not exist. Build the deployment package first.")
        sys.exit(1)
    
    priv_key = args.cp_priv_key_file.read_bytes()
    pub_key = args.ap_pub_key_file.read_bytes()
    
    cp_id, att_loc, att_date, att_customer = parse_and_modify_header(args.header_file, priv_key, pub_key)
    
    print(f"Component ID: {cp_id}")
    print(f"Attestation Location: {att_loc}")
    print(f"Attestation Date: {att_date}")
    print(f"Attestation Customer: {att_customer}")

if __name__ == "__main__":
    main()
