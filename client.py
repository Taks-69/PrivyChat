import socket
import threading
import curses
import queue
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 12345

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

def network_recv(sock, aes_key, msg_queue):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                msg_queue.put("Connection closed by server.")
                break
            try:
                message = decrypt_AES(data, aes_key)
                msg_queue.put(message)
            except Exception as e:
                msg_queue.put("Decryption error: " + str(e))
        except Exception as e:
            msg_queue.put("Network error: " + str(e))
            break

def curses_main(stdscr, sock, aes_key):
    curses.curs_set(1)
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    
    # Message window and input box
    msg_win_height = height - 3
    msg_win = curses.newwin(msg_win_height, width, 0, 0)
    input_win = curses.newwin(3, width, msg_win_height, 0)
    input_win.addstr(0, 0, "Your message: ")
    input_win.refresh()
    msg_win.scrollok(True)
    msg_queue = queue.Queue()

    # Start network receiving thread
    recv_thread = threading.Thread(target=network_recv, args=(sock, aes_key, msg_queue), daemon=True)
    recv_thread.start()

    user_input = ""
    while True:
        # Display received messages
        try:
            while True:
                msg = msg_queue.get_nowait()
                msg_win.addstr(msg + "\n")
                msg_win.refresh()
        except queue.Empty:
            pass

        # Read user input
        input_win.timeout(100)
        ch = input_win.getch()
        if ch == -1:
            continue
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if len(user_input) > 0:
                user_input = user_input[:-1]
                input_win.clear()
                input_win.addstr(0, 0, "Your message: " + user_input)
                input_win.refresh()
        elif ch in (curses.KEY_ENTER, 10, 13):
            if user_input.strip().lower() == "exit":
                break
            try:
                encrypted_msg = encrypt_AES(user_input, aes_key)
                sock.send(encrypted_msg)
            except Exception as e:
                msg_win.addstr("Sending error: " + str(e) + "\n")
                msg_win.refresh()
            msg_win.addstr("You: " + user_input + "\n")
            msg_win.refresh()
            user_input = ""
            input_win.clear()
            input_win.addstr(0, 0, "Your message: ")
            input_win.refresh()
        else:
            try:
                user_input += chr(ch)
            except:
                continue
            input_win.clear()
            input_win.addstr(0, 0, "Your message: " + user_input)
            input_win.refresh()

    sock.close()

def main():
    username = input("Enter your username: ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # Receive server public RSA key
    pub_key_data = s.recv(1024)
    server_public_key = RSA.import_key(pub_key_data)
    rsa_cipher = PKCS1_OAEP.new(server_public_key)
    
    # Generate AES key and send it encrypted
    aes_key = get_random_bytes(16)
    enc_aes_key = rsa_cipher.encrypt(aes_key)
    s.send(enc_aes_key)
    
    # Send encrypted username
    enc_username = encrypt_AES(username, aes_key)
    s.send(enc_username)
    
    print("Connection established and username sent. Launching chat interface...")
    curses.wrapper(curses_main, s, aes_key)

if __name__ == "__main__":
    main()
