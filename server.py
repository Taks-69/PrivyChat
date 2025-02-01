import socket
import threading
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '0.0.0.0'
PORT = 12345

# Generate RSA key pair
rsa_key = RSA.generate(2048)
private_key = rsa_key
public_key = rsa_key.publickey()

# List of connected clients: (conn, aes_key, username, address)
clients = []
clients_lock = threading.Lock()

def encrypt_AES(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + ciphertext

def decrypt_AES(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def broadcast_message(sender_conn, message):
    with clients_lock:
        for client in clients:
            conn, aes_key, username, addr = client
            if conn != sender_conn:
                try:
                    encrypted = encrypt_AES(message, aes_key)
                    conn.send(encrypted)
                except Exception as e:
                    logging.error("Error sending to %s: %s", addr, e)

def handle_client(conn, addr):
    logging.info("Connection established with %s", addr)
    aes_key = None
    username = None
    try:
        # Send RSA public key to client
        conn.send(public_key.export_key())
        # Receive encrypted AES key
        enc_aes_key = conn.recv(256)
        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(enc_aes_key)
        logging.info("AES key established with %s", addr)
        
        # Receive username (first encrypted message)
        enc_username = conn.recv(1024)
        username = decrypt_AES(enc_username, aes_key)
        logging.info("Username received from %s: %s", addr, username)
        
        # Add client to global list
        with clients_lock:
            clients.append((conn, aes_key, username, addr))
        
        # Notify other clients
        broadcast_message(conn, f"{username} has joined the chat.")
        
        while True:
            data = conn.recv(1024)
            if not data:
                break
            try:
                message = decrypt_AES(data, aes_key)
                logging.info("Message from %s (%s): %s", username, addr, message)
                broadcast_message(conn, f"{username}: {message}")
            except Exception as e:
                logging.error("Decryption error from %s (%s): %s", username, addr, e)
    except Exception as e:
        logging.error("Error with %s: %s", addr, e)
    finally:
        with clients_lock:
            clients[:] = [c for c in clients if c[0] != conn]
        conn.close()
        logging.info("Disconnection of %s (%s)", username if username else addr, addr)
        broadcast_message(conn, f"{username} has left the chat." if username else f"{addr} has left the chat.")

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    logging.info("Server listening on %s:%s", HOST, PORT)
    try:
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        logging.info("Server interrupted by user.")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()
