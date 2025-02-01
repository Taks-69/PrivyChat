````
# PrivyChat

PrivyChat is a secure **TCP** chat program using **RSA** for key exchange and **AES** for message encryption. It allows multiple clients to communicate confidentially via a central server.

---

## 🔹 Features
- ✅ **End-to-end encryption** with a **hybrid system (RSA + AES)**  
- ✅ **Secure key exchange** via RSA-2048  
- ✅ **Message encryption** using **AES-128 CBC** for secure conversations  
- ✅ **Multi-client support**: multiple users can join the chat  
- ✅ **Terminal-based interface** with `curses` (for the client)  

---

## 💽 Installation
### **Prerequisites**
- **Python 3.x**  
- Install dependencies:  
   ```bash
   pip install pycryptodome
````

### **Clone the project**

```bash
git clone https://github.com/Taks-69/PrivyChat.git
cd PrivyChat
```

---

## 🚀 Usage

### **1️⃣ Start the server**

```bash
python server.py
```

- The server listens for incoming connections on `0.0.0.0:12345`
- It manages key distribution and message broadcasting

### **2️⃣ Start a client**

```bash
python client.py
```

- The client connects to the server and requests a username
- It securely exchanges an AES key for encrypted communication

---

## 💻 Execution Example

### **📞 Server Side**

```
INFO - Server listening on 0.0.0.0:12345
INFO - Connection established with ('127.0.0.1', 53421)
INFO - AES key established with ('127.0.0.1', 53421)
INFO - Username received from ('127.0.0.1', 53421): Alice
INFO - Message from Alice: Hello everyone!
```

### **📝 Client Side**

```
Enter your username: Alice
Connection established and username sent. Launching chat interface...
[Alice]: Hello everyone!
```

---

## 🔐 Security

💡 **How it works?**  
1️⃣ The **server generates an RSA key pair (2048 bits)**  
2️⃣ **The client retrieves the public key** and encrypts a random AES key  
3️⃣ **The server decrypts the AES key using its private key**  
4️⃣ **Messages are then encrypted with AES-128 in CBC mode** and exchanged  

### **⚠️ Security Measures**

- 🔹 **RSA for secure AES key exchange**
- 🔹 **AES-128 in CBC mode for message encryption**
- 🔹 **Random IV per message to prevent pattern analysis**
- 🔹 **Multi-client handling with threading to avoid blocking issues**

---


## 📚 Disclaimer

> This project is for **educational purposes only**.  
> The author **is not responsible** for any misuse.

---

## 📚 License

This project is licensed under the GNU General Public License v3.0.

---

🔥 **Feel free to star ⭐ the repository if you found this project useful!** 🚀

````

