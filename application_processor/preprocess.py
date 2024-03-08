import argparse
from pathlib import Path
import sys

def read_binary_file(path):
    with open(path, 'rb') as file:
        return file.read()

def format_key_for_c_define(key):
    return ', '.join(f'0x{byte:02x}' for byte in key)

def parse_and_modify_header(header_path, ap_priv_key, cp_pub_key, ap_hash_key, ap_hash_salt, ap_hash_pin, ap_hash_token, aead_key, aead_nonce, aead_nonce_cp_boot, aead_nonce_ap_boot, aead_cipher_ap_boot):
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
        # remove #endif
        # potential bug: if header file has multiple #endif
        for line in lines:
            if line.strip().startswith('#endif'):
                break
            # if 'AP_' not in line:
            #     file.write(line)
            file.write(line)
            # if line.strip().startswith('#define AP_PIN') or line.strip().startswith('#define AP_TOKEN'):
            #     file.write(line)
            # else:
            #     if not line.strip() or line.strip().startswith('#'):
            #         file.write(line)
            #     else:
            #         break  # Stop before non-directive, non-empty lines
        file.write(f'#define AP_PRIVATE_KEY {format_key_for_c_define(ap_priv_key)}\n')
        file.write(f'#define CP_PUBLIC_KEY {format_key_for_c_define(cp_pub_key)}\n')
        file.write(f'#define AP_HASH_PIN {format_key_for_c_define(ap_hash_pin)}\n')
        file.write(f'#define AP_HASH_TOKEN {format_key_for_c_define(ap_hash_token)}\n')
        file.write(f'#define AP_HASH_KEY {format_key_for_c_define(ap_hash_key)}\n')
        file.write(f'#define AP_HASH_SALT {format_key_for_c_define(ap_hash_salt)}\n')
        file.write(f'#define AEAD_KEY {format_key_for_c_define(aead_key)}\n')
        file.write(f'#define AEAD_NONCE {format_key_for_c_define(aead_nonce)}\n')
        file.write(f'#define AEAD_NONCE_CP_BOOT {format_key_for_c_define(aead_nonce_cp_boot)}\n')
        file.write(f'#define AEAD_NONCE_AP_BOOT {format_key_for_c_define(aead_nonce_ap_boot)}\n')
        file.write(f'#define AEAD_CIPHER_AP_BOOT {format_key_for_c_define(aead_cipher_ap_boot)}\n')
        file.write(f'#endif')
        
    
    return cp_ids, cp_cnt, ap_pin, ap_token

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--ap-priv-key-file", type=Path, required=True)
    parser.add_argument("--cp-pub-key-file", type=Path, required=True)
    parser.add_argument("--hash-key-file", type=Path, required=True)
    parser.add_argument("--hash-salt-file", type=Path, required=True)
    parser.add_argument("--hash-pin-file", type=Path, required=True)
    parser.add_argument("--hash-token-file", type=Path, required=True)
    parser.add_argument("--aead-key-file", type=Path, required=True)
    parser.add_argument("--aead-nonce-file", type=Path, required=True)
    parser.add_argument("--aead-nonce-cp-boot-file", type=Path, required=True)
    parser.add_argument("--aead-nonce-ap-boot-file", type=Path, required=True)
    parser.add_argument("--aead-cipher-ap-boot-file", type=Path, required=True)
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
    
    if not args.hash_key_file.exists():
        print(f"Hash key file {args.hash_key_file} does not exist. Build the deployment package first.")
        sys.exit(1)

    if not args.hash_salt_file.exists():
        print(f"Hash salt file {args.hash_salt_file} does not exist. Build the deployment package first.")
        sys.exit(1)

    if not args.hash_pin_file.exists():
        print(f"Hash for PIN file {args.hash_pin_file} does not exist. Build the deployment package first.")
        sys.exit(1)

    if not args.hash_token_file.exists():
        print(f"Hash for token file {args.hash_token_file} does not exist. Build the deployment package first.")
        sys.exit(1)

    if not args.aead_key_file.exists():
        print(f"AEAD key file {args.aead_key_file} does not exist. Build the deployment package first.")
        sys.exit(1)

    if not args.aead_nonce_file.exists():
        print(f"AEAD nonce file {args.aead_nonce_file} does not exist. Build the deployment package first.")
        sys.exit(1)

    if not args.aead_nonce_cp_boot_file.exists():
        print(f"AEAD nonce_cp_boo file {args.aead_nonce_cp_boot_file} does not exist. Build the deployment package first.")
        sys.exit(1)

    if not args.aead_nonce_ap_boot_file.exists():
        sys.exit(1)

    if not args.aead_cipher_ap_boot_file.exists():
        sys.exit(1)
    
    priv_key = args.ap_priv_key_file.read_bytes()
    pub_key = args.cp_pub_key_file.read_bytes()
    hash_key = args.hash_key_file.read_bytes()
    hash_salt = args.hash_salt_file.read_bytes()
    hash_pin = args.hash_pin_file.read_bytes()
    hash_token = args.hash_token_file.read_bytes()
    aead_key = args.aead_key_file.read_bytes()
    aead_nonce = args.aead_nonce_file.read_bytes()
    aead_nonce_cp_boot = args.aead_nonce_cp_boot_file.read_bytes()
    aead_nonce_ap_boot = args.aead_nonce_ap_boot_file.read_bytes()
    aead_cipher_ap_boot = args.aead_cipher_ap_boot_file.read_bytes()
    
    cp_ids, cp_cnt, ap_pin, ap_token = parse_and_modify_header(args.header_file, priv_key, pub_key, hash_key, hash_salt, hash_pin, hash_token, aead_key, aead_nonce, aead_nonce_cp_boot, aead_nonce_ap_boot, aead_cipher_ap_boot)
    
    if not (ap_pin and ap_token and cp_ids and cp_cnt):
        print("Error: Could not find AP_PIN, AP_TOKEN, COMPONENT_IDS, or COMPONENT_CNT in header file.")

if __name__ == "__main__":
    main()
