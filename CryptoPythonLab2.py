import os
import argparse
import secrets 
from ftplib import FTP
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


MAGIC = b"SFA1"  
SALT_LEN = 16
NONCE_LEN = 12          
TAG_LEN = 16
KEY_LEN = 32            # 32 bytes para AES-256
PBKDF2_ITERS = 200_000  


def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=KEY_LEN,
        count=PBKDF2_ITERS,
        hmac_hash_module=SHA256
    )


def encrypt_file(in_path: str, out_path: str, password: str) -> None:
    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(password, salt)
    nonce = secrets.token_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    with open(in_path, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)


def decrypt_file(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Formato inválido: encabezado MAGIC no coincide.")

        salt = f.read(SALT_LEN)
        nonce = f.read(NONCE_LEN)
        tag = f.read(TAG_LEN)
        ciphertext = f.read()

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    with open(out_path, "wb") as f:
        f.write(plaintext)


def ftp_upload(host: str, user: str, password: str, local_path: str, remote_name: str, port: int = 21) -> None:
    with FTP() as ftp:
        ftp.connect(host, port, timeout=15)
        ftp.login(user=user, passwd=password)
        with open(local_path, "rb") as f:
            ftp.storbinary(f"STOR {remote_name}", f)


def ftp_download(host: str, user: str, password: str, remote_name: str, local_path: str, port: int = 21) -> None:
    with FTP() as ftp:
        ftp.connect(host, port, timeout=15)
        ftp.login(user=user, passwd=password)
        with open(local_path, "wb") as f:
            ftp.retrbinary(f"RETR {remote_name}", f.write)


def main():
    parser = argparse.ArgumentParser(description="Cifrado AES para archivos con FTP (subir o descargar).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Cifrar un archivo local")
    p_enc.add_argument("-i", "--in", dest="infile", required=True)
    p_enc.add_argument("-o", "--out", dest="outfile", required=True)


    p_dec = sub.add_parser("decrypt", help="Descifrar un archivo local")
    p_dec.add_argument("-i", "--in", dest="infile", required=True)
    p_dec.add_argument("-o", "--out", dest="outfile", required=True)

    p_up = sub.add_parser("upload", help="Cifra y sube a FTP")
    p_up.add_argument("--host", required=True)
    p_up.add_argument("--user", required=True)
    p_up.add_argument("--port", type=int, default=21)
    p_up.add_argument("-i", "--in", dest="infile", required=True, help="archivo local a cifrar")
    p_up.add_argument("--remote", required=True, help="nombre remoto (archivo cifrado)")

    p_down = sub.add_parser("download", help="Descarga de FTP y descifra")
    p_down.add_argument("--host", required=True)
    p_down.add_argument("--user", required=True)
    p_down.add_argument("--port", type=int, default=21)
    p_down.add_argument("--remote", required=True, help="nombre remoto (archivo cifrado)")
    p_down.add_argument("-o", "--out", dest="outfile", required=True, help="archivo local descifrado de salida")
    p_down.add_argument("--tmp", default="download.enc", help="ruta temporal para el archivo cifrado descargado")

    args = parser.parse_args()

    if args.cmd in ("encrypt", "decrypt"):
        pw = getpass("Contraseña para cifrado: ")

    if args.cmd == "encrypt":
        encrypt_file(args.infile, args.outfile, pw)
        print(f"[OK] Archivo cifrado guardado en: {args.outfile}")

    elif args.cmd == "decrypt":
        decrypt_file(args.infile, args.outfile, pw)
        print(f"[OK] Archivo descifrado guardado en: {args.outfile}")

    elif args.cmd == "upload":
        ftp_pw = getpass("Contraseña FTP: ")
        crypto_pw = getpass("Contraseña para cifrado (AES): ")

        enc_path = args.infile + ".enc"
        encrypt_file(args.infile, enc_path, crypto_pw)
        ftp_upload(args.host, args.user, ftp_pw, enc_path, args.remote, port=args.port)
        print(f"[OK] Subido a FTP como: {args.remote}")
        os.remove(enc_path)

    elif args.cmd == "download":
        ftp_pw = getpass("Contraseña FTP: ")
        crypto_pw = getpass("Contraseña para cifrado (AES): ")

        ftp_download(args.host, args.user, ftp_pw, args.remote, args.tmp, port=args.port)
        decrypt_file(args.tmp, args.outfile, crypto_pw)
        print(f"[OK] Descargado y descifrado en: {args.outfile}")
        os.remove(args.tmp)


if __name__ == "__main__":
    main()
