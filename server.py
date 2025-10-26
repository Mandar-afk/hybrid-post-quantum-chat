# server.py
# User B (server / receiver)
# Requirements: cryptography, liboqs-python

import socket, struct, hashlib, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs

HOST = "127.0.0.1"
PORT = 65432

# ---------- helpers ----------
def send_bytes(conn, b: bytes):
    conn.sendall(struct.pack("!I", len(b)))
    conn.sendall(b)

def recv_bytes(conn):
    raw = conn.recv(4)
    if not raw:
        raise ConnectionError("socket closed")
    n = struct.unpack("!I", raw)[0]
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed during recv")
        data += chunk
    return data

def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub

def rsa_decrypt_with_private(privkey, ciphertext):
    return privkey.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------- server logic ----------
def main():
    # generate RSA keys for server (User B)
    priv_b, pub_b = generate_rsa_keypair()
    pem_pub_b = pub_b.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)

    print("[server] RSA keys generated. Listening...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print(f"[server] Connected by {addr}")

            # 1) Receive client's RSA public key
            pem_pub_a = recv_bytes(conn)
            print("[server] Received client RSA public key (len {})".format(len(pem_pub_a)))

            # 2) Send server's RSA public key
            send_bytes(conn, pem_pub_b)
            print("[server] Sent server RSA public key to client")

            # 3) Kyber: server generates keypair and sends public key to client
            enabled = oqs.get_enabled_kem_mechanisms()
            preferred = None
            for candidate in ("Kyber1024", "Kyber768", "Kyber512", "kyber_1024", "kyber_768", "kyber_512"):
                if candidate in enabled:
                    preferred = candidate
                    break
            if preferred is None:
                preferred = enabled[0]
            print("[server] Using KEM:", preferred)

            with oqs.KeyEncapsulation(preferred) as kem_b:
                pk_b = kem_b.generate_keypair()
                send_bytes(conn, pk_b)
                print("[server] Sent Kyber public key to client (len {})".format(len(pk_b)))

                # 4) Receive RSA-encrypted AES key (from client)
                encrypted_aes_key = recv_bytes(conn)
                print("[server] Received RSA-encrypted AES key (len {})".format(len(encrypted_aes_key)))
                aes_key_classical = rsa_decrypt_with_private(priv_b, encrypted_aes_key)
                print("[server] Decrypted classical AES key (len {})".format(len(aes_key_classical)))

                # 5) Receive Kyber ciphertext (from client) and decapsulate to shared secret
                ciphertext_kem = recv_bytes(conn)
                print("[server] Received Kyber ciphertext (len {})".format(len(ciphertext_kem)))
                # server decapsulates
                if hasattr(kem_b, "decap_secret"):
                    shared_secret_b = kem_b.decap_secret(ciphertext_kem)
                elif hasattr(kem_b, "decap"):
                    shared_secret_b = kem_b.decap(ciphertext_kem)
                else:
                    raise RuntimeError("No decapsulation method available on kem_b")
                print("[server] Decapsulated Kyber shared secret (len {})".format(len(shared_secret_b)))

                # 6) Derive final AES key: SHA256(aes_key_classical || kyber_shared_secret)
                final_aes_key = hashlib.sha256(aes_key_classical + shared_secret_b).digest()
                print("[server] Derived final AES key (len {})".format(len(final_aes_key)))

                # 7) Receive AES-GCM encrypted message (nonce + ciphertext)
                nonce = recv_bytes(conn)
                ct = recv_bytes(conn)
                aad = recv_bytes(conn)  # client sends AAD too
                aesgcm = AESGCM(final_aes_key)
                try:
                    pt = aesgcm.decrypt(nonce, ct, aad)
                    print("[server] Received message (decrypted):", pt.decode())
                except Exception as e:
                    print("[server] Decryption failed:", e)
                    return

                # 8) (Optional) reply to client: send an AES-GCM encrypted response
                reply = b"This is the server replying! love you client. <3"
                nonce2 = os.urandom(12)
                ct2 = aesgcm.encrypt(nonce2, reply, aad)
                send_bytes(conn, nonce2)
                send_bytes(conn, ct2)
                send_bytes(conn, aad)
                print("[server] Sent encrypted reply to client")

    print("[server] connection closed")

if __name__ == "__main__":
    main()
