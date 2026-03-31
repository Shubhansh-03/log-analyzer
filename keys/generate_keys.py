import os
from Crypto.PublicKey import RSA

def generate_key_pair(output_dir, prefix):
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open(os.path.join(output_dir, f"{prefix}_private.pem"), 'wb') as f:
        f.write(private_key)
        
    public_key = key.publickey().export_key()
    with open(os.path.join(output_dir, f"{prefix}_public.pem"), 'wb') as f:
        f.write(public_key)
    
    print(f"Generated {prefix} key pair.")

if __name__ == "__main__":
    os.makedirs("keys", exist_ok=True)
    generate_key_pair("keys", "client")
    generate_key_pair("keys", "server")
    print("Keys successfully generated and saved to 'keys/' directory.")
