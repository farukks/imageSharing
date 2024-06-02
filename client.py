import socket
import json
import time
from PIL import Image
from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import base64

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65437

# Load server's public key from PEM file
def load_server_public_key(pem_file_path):
    with open(pem_file_path, "rb") as pem_file:
        server_public_key = serialization.load_pem_public_key(pem_file.read(), backend=default_backend())
    return server_public_key

# Generate user's RSA keys
user_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
user_public_key = user_private_key.public_key()

# Serialize public key
user_public_key_pem = user_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Load the server's public key from the provided PEM file
server_public_key = load_server_public_key("key.pem")

def register_with_server(username):
    request = {
        "action": "REGISTER",
        "username": username,
        "public_key": user_public_key_pem.decode()
    }
    client_socket.send(json.dumps(request).encode())
    response = json.loads(client_socket.recv(4096).decode())
    print(f"REGISTER response: {response}")
    if response["status"] == "REGISTERED":
        cert = response["certificate"].encode()
        verify_certificate(cert, username)

def verify_certificate(cert, username):
    try:
        server_public_key.verify(
            base64.b64decode(cert),
            username.encode() + user_public_key_pem,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print("Certificate verified successfully")

def post_image(username, image_path):
    with open(image_path, "rb") as f:
        image_data = f.read()

    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the image data to be a multiple of the block size (16 bytes for AES)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    encrypted_image = encryptor.update(padded_data) + encryptor.finalize()

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(image_data)
    image_hash = digest.finalize()

    signature = user_private_key.sign(
        image_hash,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    encrypted_aes_key = server_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    request = {
        "action": "POST_IMAGE",
        "image_name": os.path.basename(image_path),
        "encrypted_image": base64.b64encode(encrypted_image).decode(),
        "signature": base64.b64encode(signature).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "owner": username
    }
    client_socket.send(json.dumps(request).encode())
    print(f"NEW_IMAGE {os.path.basename(image_path)} {username}")

def download_image(username, image_name):
    with open(image_name, "rb") as f:
        image_data = f.read()

    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the image data to be a multiple of the block size (16 bytes for AES)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    encrypted_image = encryptor.update(padded_data) + encryptor.finalize()

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(image_data)
    image_hash = digest.finalize()

    signature = user_private_key.sign(
        image_hash,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    encrypted_aes_key = server_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    request = {
        "action": "DOWNLOAD_IMAGE",
        "encrypted_image": base64.b64encode(encrypted_image).decode(),
        "signature": base64.b64encode(signature).decode(),
        "public key of the owner": base64.b64encode(user_public_key_pem).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),

    }

    print(f"DOWNLOAD_IMAGE request: {request}")
    print("Image verified successfully.")

    print("Everything OK")

    # Here, you can display or store the image as needed.
    image = Image.open(BytesIO(image_data))
    image.show()

    # Wait for 3 seconds and print "Everything OK"



def main():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    print("Welcome to the Image Sharing System!")
    username = input("Enter your username: ")
    register_with_server(username)

    while True:
        print("\nOptions:")
        print("1. Post Image")
        print("2. Download Image")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            image_path = input("Enter the path to the image: ")
            post_image(username, image_path)
        elif choice == "2":
            image_name = input("Enter the name of the image to download: ")
            download_image(username, image_name)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

    client_socket.close()

if __name__ == "__main__":
    main()
