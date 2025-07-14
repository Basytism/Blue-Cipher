# Blue Cipher (Encrypted Bluetooth Morse Messenger)
# By: Abdul Basit Noor (Synergyspheres 3.0 Edition)

# ------------------ Imports ------------------ #
import bluetooth
from cryptography.fernet import Fernet
import time

# ------------------ Morse Code Dict ------------------ #
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..',
    '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
    '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----',
    ' ': '/', '.': '.-.-.-', ',': '--..--', '?': '..--..'
}

REVERSE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

# ------------------ Morse Code Functions ------------------ #
def text_to_morse(text):
    return ' '.join(MORSE_CODE_DICT.get(c.upper(), '') for c in text)

def morse_to_text(morse):
    return ''.join(REVERSE_DICT.get(code, '') for code in morse.split())

# ------------------ Encryption ------------------ #
key = Fernet.generate_key()
cipher = Fernet(key)

# Optionally print this key and share securely
print("[KEY] Share this securely:", key.decode())

def encrypt_message(msg):
    return cipher.encrypt(msg.encode())

def decrypt_message(token):
    return cipher.decrypt(token).decode()

# ------------------ Bluetooth Sending ------------------ #
def send_bluetooth_message(address, message):
    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    try:
        sock.connect((address, 1))
        sock.send(message)
        print("[SENT] Message sent over Bluetooth.")
    except Exception as e:
        print("[ERROR]", e)
    finally:
        sock.close()

# ------------------ Bluetooth Receiving ------------------ #
def receive_bluetooth_message():
    server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    server_sock.bind(("", 1))
    server_sock.listen(1)
    print("[WAITING] Listening for connection...")
    client_sock, address = server_sock.accept()
    print(f"[CONNECTED] From {address}")
    data = client_sock.recv(1024)
    client_sock.close()
    server_sock.close()
    return data.decode()

# ------------------ Main CLI ------------------ #
def main():
    mode = input("Send or Receive? (s/r): ").lower()

    if mode == 's':
        addr = input("Enter receiver Bluetooth MAC address: ")
        msg = input("Enter your message: ")
        encrypted = encrypt_message(msg)
        morse_msg = text_to_morse(encrypted.decode())
        send_bluetooth_message(addr, morse_msg)

    elif mode == 'r':
        morse_received = receive_bluetooth_message()
        encrypted_text = morse_to_text(morse_received)
        try:
            decrypted = decrypt_message(encrypted_text.encode())
            print("[DECRYPTED MESSAGE]", decrypted)
        except Exception as e:
            print("[DECRYPT ERROR]", e)

    else:
        print("Invalid mode.")

# ------------------ Execute ------------------ #
if __name__ == "__main__":
    main()
