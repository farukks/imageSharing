import socket
import threading
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65437

# Generate server's RSA keys
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
server_public_key = server_private_key.public_key()

# Store user data
user_data = {}
images = {}

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(4096).decode()
            if not message:
                break

            request = json.loads(message)
            action = request.get("action")

            if action == "REGISTER":
                username = request.get("username")
                user_public_key = request.get("public_key").encode()
                cert = sign_certificate(username, user_public_key)
                user_data[username] = {
                    "public_key": user_public_key,
                    "cert": cert
                }
                response = {"status": "SUCCESS", "cert": cert.decode()}
                client_socket.send(json.dumps(response).encode())

            elif action == "POST_IMAGE":
                image_name = request.get("image_name")
                encrypted_image = request.get("encrypted_image").encode()
                signature = request.get("signature").encode()
                encrypted_aes_key = request.get("encrypted_aes_key").encode()
                iv = request.get("iv").encode()
                owner = request.get("owner")
                images[image_name] = {
                    "encrypted_image": encrypted_image,
                    "signature": signature,
                    "encrypted_aes_key": encrypted_aes_key,
                    "iv": iv,
                    "owner": owner
                }
                print(f"NEW_IMAGE {image_name} {owner}")
                notify_users(image_name, owner)

            elif action == "DOWNLOAD":
                image_name = request.get("image_name")
                username = request.get("username")
                image = images.get(image_name)
                if image:
                    owner_cert = user_data[image["owner"]]["cert"]
                    encrypted_aes_key = image["encrypted_aes_key"]
                    encrypted_aes_key_for_user = encrypt_with_public_key(encrypted_aes_key, user_data[username]["public_key"])
                    response = {
                        "encrypted_image": image["encrypted_image"].decode(),
                        "signature": image["signature"].decode(),
                        "owner_cert": owner_cert.decode(),
                        "encrypted_aes_key": encrypted_aes_key_for_user.decode(),
                        "iv": image["iv"].decode()
                    }
                    client_socket.send(json.dumps(response).encode())
                else:
                    response = {"status": "ERROR", "message": "Image not found"}
                    client_socket.send(json.dumps(response).encode())

        except Exception as e:
            print(f"Error: {e}")
            break
    client_socket.close()

def sign_certificate(username, public_key):
    signature = server_private_key.sign(
        username.encode() + public_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature)

def notify_users(image_name, owner_name):
    notification = json.dumps({"action": "NEW_IMAGE", "image_name": image_name, "owner_name": owner_name})
    for user in user_data.values():
        if "socket" in user:
            user["socket"].send(notification.encode())

def encrypt_with_public_key(data, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"[LISTENING] Server is listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

start_server()
