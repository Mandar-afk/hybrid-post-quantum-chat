# client.py
# User A (client / initiator)
# Requirements: cryptography, liboqs-python

import socket, struct, hashlib, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs

HOST = "127.0.0.1"
PORT = 65432

# ---------- helpers ----------
def send_bytes(sock, b: bytes):
    sock.sendall(struct.pack("!I", len(b)))
    sock.sendall(b)

def recv_bytes(sock):
    raw = sock.recv(4)
    if not raw:
        raise ConnectionError("socket closed")
    n = struct.unpack("!I", raw)[0]
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed during recv")
        data += chunk
    return data

def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub

def rsa_encrypt_with_public(pubkey, plaintext):
    return pubkey.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------- client logic ----------
def main():
    # generate RSA keys for client (User A)
    priv_a, pub_a = generate_rsa_keypair()
    pem_pub_a = pub_a.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("[client] Connected to server")

        # 1) Send client's RSA public key
        send_bytes(sock, pem_pub_a)
        print("[client] Sent RSA public key to server")

        # 2) Receive server's RSA public key
        pem_pub_b = recv_bytes(sock)
        print("[client] Received server RSA public key (len {})".format(len(pem_pub_b)))
        # load server public key (if needed)
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub_b = load_pem_public_key(pem_pub_b)

        # 3) Receive server's Kyber public key
        pk_b = recv_bytes(sock)
        print("[client] Received Kyber public key (len {})".format(len(pk_b)))

        # 4) Generate classical AES key and send RSA-encrypted version to server
        aes_key_classical = os.urandom(32)
        encrypted_aes_key = rsa_encrypt_with_public(pub_b, aes_key_classical)
        send_bytes(sock, encrypted_aes_key)
        print("[client] Sent RSA-encrypted classical AES key (len {})".format(len(encrypted_aes_key)))

        # 5) Encapsulate using pk_b (client side) to obtain ciphertext and shared_secret
        enabled = oqs.get_enabled_kem_mechanisms()
        # pick same mechanism as server (we assume server used first available)
        preferred = None
        for candidate in ("Kyber1024", "Kyber768", "Kyber512", "kyber_1024", "kyber_768", "kyber_512"):
            if candidate in enabled:
                preferred = candidate
                break
        if preferred is None:
            preferred = enabled[0]
        with oqs.KeyEncapsulation(preferred) as kem_a:
            # your binding may have encap_secret or encap; try common names
            if hasattr(kem_a, "encap_secret"):
                res = kem_a.encap_secret(pk_b)
            elif hasattr(kem_a, "encap"):
                res = kem_a.encap(pk_b)
            else:
                raise RuntimeError("No encapsulation method found on client kem")
            # normalize result
            if isinstance(res, tuple) and len(res) == 2:
                ciphertext_kem, shared_secret_a = res[0], res[1]
            elif isinstance(res, (bytes, bytearray)):
                ciphertext_kem = None
                shared_secret_a = res
            else:
                raise RuntimeError("Unexpected encapsulation result shape")
        print("[client] Encapsulated Kyber secret (shared len {})".format(len(shared_secret_a)))

        # 6) Send Kyber ciphertext to server
        if ciphertext_kem is None:
            # unlikely; but still send empty marker
            send_bytes(sock, b"")
        else:
            send_bytes(sock, ciphertext_kem)
        print("[client] Sent Kyber ciphertext (len {})".format(len(ciphertext_kem) if ciphertext_kem else 0))

        # 7) Derive final AES key
        final_aes_key = hashlib.sha256(aes_key_classical + shared_secret_a).digest()
        print("[client] Derived final AES key (len {})".format(len(final_aes_key)))

        # 8) Send an AES-GCM encrypted message
        aesgcm = AESGCM(final_aes_key)
        nonce = os.urandom(12)
        aad = b"hybrid-demo-aad"
        plaintext = b"This is the client speaking! love you server."
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        send_bytes(sock, nonce)
        send_bytes(sock, ct)
        send_bytes(sock, aad)
        print("[client] Sent encrypted message")

        # 9) Optionally receive server reply (nonce + ct + aad)
        nonce2 = recv_bytes(sock)
        ct2 = recv_bytes(sock)
        aad2 = recv_bytes(sock)
        try:
            pt2 = aesgcm.decrypt(nonce2, ct2, aad2)
            print("[client] Received reply (decrypted):", pt2.decode())
        except Exception as e:
            print("[client] Reply decryption failed:", e)

    print("[client] Done")

if __name__ == "__main__":
    main()
