import hashlib
import random
import socket
import threading

import my_enc_decrp as ENC_DECRP


def login(cl_sock):

    while True:
        nonce = cl_sock.recv(1024).decode()
        print("nonce received", nonce)

        username = input("Username: ")
        cl_sock.send(username.encode())

        password = input("Password: ")
        enc_password = hashlib.sha3_512((password+nonce).encode()).hexdigest()
        cl_sock.send(enc_password.encode())
        print("enc password",enc_password)

        response = cl_sock.recv(1024).decode()

        if response == "user_notfound":
            print(" User not found")
            return False

        elif response == "passwordfailed":
            print(" Wrong password, try again")
            continue

        elif response == "blocked":
            print(" Account blocked for 24 hours")
            return False

        elif response == "success":
            print(" Login success")
            return True

        else:
            print("️ Unknown response from server:", response)
            return False




def receive_messages(sock, dh_secretkey):
    global current_file, file_buffer

    current_file = None
    file_buffer = b""
    received_file_data = b""  # to store entire file content

    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("\n Connection closed by server.")
                break

            file_buffer += data

            while True:
                # 🔹 EOF marker for file download
                if file_buffer.startswith(b"EOF"):
                    file_buffer = file_buffer[3:]
                    if current_file:
                        current_file.close()
                        current_file = None
                        print("\n File download complete.")

                        # Print full file content
                        print("\n Received file content:\n")
                        try:
                            print(received_file_data.decode())
                        except:
                            print(received_file_data)
                        print("\nYou: ", end="")
                        received_file_data = b""
                    continue

                # 🔹 Check for file packet header (seq|len|)
                if b"\n" not in file_buffer:
                    break  # header incomplete, wait for more data

                header, rest = file_buffer.split(b"\n", 1)

                if b"|" not in header:
                    break  # not a file header, treat as normal message

                try:
                    seq_no, cipher_len = map(int, header.decode().split("|")[:2])
                except:
                    break  # malformed header, wait for more data

                mac_len = 32  # HMAC-SHA256
                total_len = cipher_len + mac_len

                if len(rest) < total_len:
                    break  # wait for full packet

                cipher_data = rest[:cipher_len]
                mac = rest[cipher_len:cipher_len + mac_len]
                file_buffer = rest[total_len:]

                # 🔹 Verify MAC
                if not ENC_DECRP.verify_mac(cipher_data, seq_no, dh_secretkey, mac):
                    print("\n MAC verification failed! File corrupted.\nYou: ", end="")
                    if current_file:
                        current_file.close()
                        current_file = None
                    continue

                # 🔹 Open file lazily
                if current_file is None:
                    current_file = open("downloaded_file.txt", "wb")

                # 🔹 Decrypt and write chunk
                plaintext = ENC_DECRP.aes_decrypt(cipher_data, dh_secretkey)
                current_file.write(plaintext)
                received_file_data += plaintext
                continue  # process next packet

            # 🔹 Handle normal messages or "file not found"
            if file_buffer:
                try:
                    msg = ENC_DECRP.aes_decrypt(file_buffer, dh_secretkey).decode()
                    if "file not found" in msg:
                        print(f"\n Server says: {msg}\nYou: ", end="")
                    elif "UNKNOWN_COMMAND" in msg:
                        print(f"\n Server says: {msg}\nYou: ", end="")
                    else:
                        print(f"\rSERVER: {msg}\nYou: ", end="")
                    file_buffer = b""  # clear buffer
                except:
                    pass  # incomplete message, wait for more data

        except Exception as e:
            print("\n Connection lost:", e)
            break





def client_entrypoint():
    cl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cl_sock.connect(('localhost', 9090))
    except ConnectionRefusedError:
        print("Server is offline.")
        return

    if not login(cl_sock):
        cl_sock.close()
        return

    #get deffie hellman p, g and compute secret key after login
    with open("globalvariable.txt", "r") as f:
        line = f.readline()
    dh_p = int(line.split("|")[0])
    dh_g = int(line.split("|")[1])
    a = random.randint(2, dh_p)
    A = pow(dh_g, a, dh_p)
    cl_sock.send(str(A).encode())
    server_secret = int(cl_sock.recv(1024).decode())
    dh_secretkey = pow(server_secret, a, dh_p)

    recv_thread = threading.Thread(target=receive_messages, args=(cl_sock, dh_secretkey))
    recv_thread.daemon = True
    recv_thread.start()


    print(" Commands  GET | INFO | SIZE | 'exit' to quit ---")
    while True:
        print("")
        message = input("You: ")

        if message.lower() == "exit":
            encrypted_exit = ENC_DECRP.aes_encrypt(b"exit", dh_secretkey)
            cl_sock.send(encrypted_exit)
            break

        encrypted_msg = ENC_DECRP.aes_encrypt(message.encode(), dh_secretkey)
        cl_sock.send(encrypted_msg)

    cl_sock.close()
    print("Disconnected.")

if __name__ == "__main__":
    client_entrypoint()