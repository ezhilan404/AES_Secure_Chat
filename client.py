# client.py (AES version)

import socket
import threading
from aes_cipher import encrypt_message, decrypt_message

SERVER_HOST = "127.0.0.1"   
SERVER_PORT = 5000

SALT = b"fixed_salt_1234"  


def handle_receive(sock, password: str):
    """
    Receive encrypted tokens from server,
    decrypt using AES (Fernet), print plaintext.
    """
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("[!] Server disconnected.")
                break

            try:
                message = decrypt_message(data, password, SALT)
                print(f"\n[Server]: {message}")
            except Exception as e:
                print(f"\n[!] Decryption/Integrity error: {e}")

        except ConnectionResetError:
            print("[!] Connection reset by server.")
            break
        except KeyboardInterrupt:
            print("\n[!] Receive thread interrupted.")
            break


def handle_send(sock, password: str):
    """
    Read input from client-side user, encrypt using AES, send to server.
    """
    try:
        while True:
            msg = input()
            if msg.lower() in ("quit", "exit"):
                print("[*] Closing connection.")
                sock.close()
                break

            token = encrypt_message(msg, password, SALT)
            sock.sendall(token)
    except (BrokenPipeError, ConnectionResetError):
        print("[!] Connection lost.")
    except KeyboardInterrupt:
        print("\n[!] Send loop interrupted.")
        sock.close()


def main():
    print("=== AES Encrypted Chat Client (Educational v1) ===")
    password = input("Enter shared password: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

        recv_thread = threading.Thread(
            target=handle_receive, args=(sock, password), daemon=True
        )
        recv_thread.start()

        handle_send(sock, password)


if __name__ == "__main__":
    main()
