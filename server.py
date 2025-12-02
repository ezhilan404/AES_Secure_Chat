import socket
import threading
from aes_cipher import decrypt_message, encrypt_message


HOST = "0.0.0.0"
PORT = 5000
SALT = b"fixed_salt_1234"


def handle_receive(conn, password:str):
    
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("[!] Connection closed by client.")
                break

            try:
                message = decrypt_message(data, password, salt=SALT)
                print(f"[Client]: {message}")
            except Exception as e:
                print(f"[!] Decryption error: {e}") 
            
        except ConnectionResetError:
            print(f"[!] Connection reset by client.")
            break
        except KeyboardInterrupt:
            print("\n[!] Server shutting down.")
            break  


def handle_send(conn, password:str):

    try:
        while True:
            message = input()
            if message.lower() in ("exit", "quit"):
                print("[*] Closing connection.")
                conn.close()
                break
            
            token = encrypt_message(message, password, salt=SALT)
            conn.sendall(token)
        
    except (BrokenPipeError, ConnectionResetError):
        print("[!] Connection lost.")
    except KeyboardInterrupt:
        print("\n[!] Send loop interrupted.")
        conn.close()


def main():
    password = input("Enter the shared password for encryption: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[*] Server listening on {HOST}:{PORT}")

        conn, addr = server_socket.accept()
        print(f"[+] Connection established with {addr}")

        receive_thread = threading.Thread(target=handle_receive, args=(conn, password))
        send_thread = threading.Thread(target=handle_send, args=(conn, password))

        receive_thread.start()
        send_thread.start()

        receive_thread.join()
        send_thread.join()

        print("[*] Server shutting down.")


if __name__ == "__main__":
    main()
    



