"""
Extracts all private RSA keys from all files in the current directory
Keys are stored into the file "private-keys.txt"
"""

import os
import re
import base64
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

PUBLICKEYBLOB = 0x6
PRIVATEKEYBLOB = 0x7
BLOBVERSION = 0x2
CALG_RSA_KEYX = 0x0000a400

RSA1_MAGIC = 0x31415352 # 'RSA1'
RSA2_MAGIC = 0x32415352 # 'RSA2'

OUTPUT_FILE = "private-keys.txt"
BEGIN_MARKER = b"-----BEGIN RSA PRIVATE KEY-----"
END_MARKER = b"-----END RSA PRIVATE KEY-----"

PEM_RSA_KEY_REGEX = re.compile(BEGIN_MARKER + b".{2048,4096}" + END_MARKER, re.DOTALL)


def normalize_pem_key(rsa_private_key):
    """Removes unnecessary chars from the string"""

    # We need strings, not bytes
    begin_marker_str = BEGIN_MARKER.decode("ascii")
    end_marker_str = END_MARKER.decode("ascii")

    # Remove the newlines from JSON-like private key
    rsa_private_key = rsa_private_key.replace("\\r", "").replace("\\n", "")
    return rsa_private_key


def make_private_blob(privkey: rsa.RSAPrivateKey) -> bytes:

    # Dissect the private key
    numbers = privkey.private_numbers()
    p = numbers.p
    q = numbers.q
    d = numbers.d
    dmp1 = numbers.dmp1 # d mod (p-1)
    dmq1 = numbers.dmq1 # d mod (q-1)
    iqmp = numbers.iqmp # q^{-1} mod p
    pub_n = numbers.public_numbers.n
    pub_e = numbers.public_numbers.e

    modulus_bitlen = pub_n.bit_length()
    modulus_bytelen = (modulus_bitlen + 7) // 8
    prime_bytelen = ( (p.bit_length() + 7) // 8 )

    # Construct the BLOBHEADER structure
    header = struct.pack('<BBH', PRIVATEKEYBLOB, BLOBVERSION, 0)
    header += struct.pack('<I', CALG_RSA_KEYX)

    # Construct the RSAPUBKEY with 'RSA2' magic
    rsapubkey = struct.pack('<I', RSA2_MAGIC)
    rsapubkey += struct.pack('<I', modulus_bitlen)
    rsapubkey += struct.pack('<I', pub_e)

    # Converts bignum to bytes (big endian)
    def int_to_bytes(n: int, length: int) -> bytes:
        return n.to_bytes(length, byteorder="big")

    # The order for the private-key BLOB body (all little-endian, each field padded):
    # modulus (n), prime1 (p), prime2 (q), exponent1 (d mod (p-1)), exponent2 (d mod (q-1)), coefficient (iqmp), privateExponent (d)
    #def int_to_bytes_pad(value: int, size: int) -> bytes:
    #    b = int_to_bytes(value, size)[::-1]
    #    return b

    # Construct the modulus
    mod_be = int_to_bytes(pub_n, modulus_bytelen)
    mod_le = mod_be[::-1]

    # Construct the other big numbers
    p_be = int_to_bytes(p, prime_bytelen)
    p_le = p_be[::-1]
    q_be = int_to_bytes(q, prime_bytelen)
    q_le = q_be[::-1]
    dmp1_be = int_to_bytes(dmp1, prime_bytelen)
    dmp1_le = dmp1_be[::-1]
    dmq1_be = int_to_bytes(dmq1, prime_bytelen)
    dmq1_le = dmq1_be[::-1]
    iqmp_be = int_to_bytes(iqmp, prime_bytelen)
    iqmp_le = iqmp_be[::-1]

    # Private exponent d should be same length as modulus
    d_be = int_to_bytes(d, modulus_bytelen)
    d_le = d_be[::-1]

    # Construct the whole RSA key
    return header + rsapubkey + mod_le + p_le + q_le + dmp1_le + dmq1_le + iqmp_le + d_le

def rsa_pem_to_capi(rsa_private_key_b64):

    try:
        # Convert into RSA structure. We need bytes for that, not string
        rsa_private_key_b64 = rsa_private_key_b64.encode("ascii")
        rsa_private_key = load_pem_private_key(rsa_private_key_b64, password=None, backend=default_backend())

        # Is it an instance of RSA private key?
        if not isinstance(rsa_private_key, rsa.RSAPrivateKey):
            return None
        
        # Convert to RSA key in CAPI format
        rsa_private_key_capi = make_private_blob(rsa_private_key)
        
        # Convert to Base64
        return base64.b64encode(rsa_private_key_capi).decode("ascii")

    except Exception as e:
        return None


def extract_pem_keys(all_keys, data: bytes):
    """Extract PEM RSA keys from a binary blob."""

    key_count = None
    match_list = PEM_RSA_KEY_REGEX.findall(data)

    if len(match_list):
        key_count = 0
        for match_item in match_list:

            # Extract the private RSA key and convert to CryptoAPI format
            rsa_private_key = match_item.decode("ascii")
            rsa_private_key = normalize_pem_key(rsa_private_key)
            rsa_private_key = rsa_pem_to_capi(rsa_private_key)

            # Is the key already in the list?
            if rsa_private_key in all_keys:
                continue

            # Insert the key to the list
            all_keys.append(rsa_private_key)
            key_count += 1

    return key_count


def main():

    all_keys = []

    # Load already-known-keys from output file
    with open(OUTPUT_FILE, "r") as inp:
        for line in inp:
            rsa_private_key = line.strip()
            if rsa_private_key == "" or rsa_private_key in all_keys:
                continue
            all_keys.append(rsa_private_key)

    # Load keys from samples of decryptors
    for filename in os.listdir("."):

        # Construct the full path name
        path = os.path.abspath(filename)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()

        # Extract the PEM RSA key and add it to the collection
        key_count = extract_pem_keys(all_keys, data)
        if key_count is None:
            continue
        if key_count == 0:
            print("[*] %s ... (Duplicate)" % filename)
        elif key_count > 0:
            print("[*] %s ... (OK)" % filename)

    # Write all found keys (one per line or block)
    with open(OUTPUT_FILE, "w") as out:
        for key in all_keys:
            out.write(key.strip() + "\n")
    print(f"{len(all_keys)} RSA private extracted to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()