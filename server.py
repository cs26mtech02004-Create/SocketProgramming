import random
import secrets
import socket
import threading
from datetime import datetime

#my own file to import
import GloblaVariableGeneration
import login
import FileHandlingSocket
import  my_enc_decrp
clients = []
def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message.encode())
            except:
                client.close()
                clients.remove(client)






def client_history(client_name,request, response=None):
    timestamp = datetime.now().isoformat()
    with open("client_historybook.log","a") as fl:
        fl.write(f"{timestamp} | {client_name} | {request} | {response}\n")



def handling_client(cl_sock, addr):
        print("Connected with", addr)

        while True:
            nonce = secrets.token_hex(8)
            cl_sock.send(nonce.encode())
            print("nonce sent", nonce)

            username = cl_sock.recv(1024).decode()
            password = cl_sock.recv(1024).decode()

            login_response = login.verify_client(username, password, nonce)

            if login_response == "user_notfound":
                cl_sock.send("user_notfound".encode())
                cl_sock.close()
                return

            elif login_response == "passwordfailed":
                cl_sock.send("passwordfailed".encode())
                continue

            elif login_response == "blocked":
                cl_sock.send("blocked".encode())
                cl_sock.close()
                return

            else:
                cl_sock.send("success".encode())
                clients.append(cl_sock)
                print(f"{login_response} joined")
                break

            # deffie hellman secret key create karna h

        with open("globalvariable.txt", "r") as f:
            line = f.readline()
        dh_p = int(line.split("|")[0])
        dh_g = int(line.split("|")[1])
        b = random.randint(2, dh_p)
        B = pow(dh_g, b, dh_p)
        cl_sock.send(str(B).encode())
        client_secret = int(cl_sock.recv(1024).decode())
        secret_key = pow(client_secret, b, dh_p)
        print(secret_key)

        # ---- CHAT PHASE ----
        while True:
            try:
                message = cl_sock.recv(1024)
                message = my_enc_decrp.aes_decrypt(message, secret_key).decode()
                if not message or message.lower() == "exit":
                    break

                print(f"{login_response}: {message}")

                message = message.strip()
                command_parts = message.split(maxsplit=1)
                cmd = command_parts[0]
                file_name = command_parts[1] if len(command_parts) > 1 else None
                # print(F"file_name: {file_name} AND COMMAND: {cmd}")
                file_response = FileHandlingSocket.filemgmtcommand(cmd, secret_key, file_name)
                if cmd == "GET":
                    for i in range(0, len(file_response)):
                        cl_sock.sendall(file_response[i])
                    print("chunks sended to client")
                else:
                    print(f"response from file handle to server{file_response}")
                    cl_sock.send(file_response)
                client_history(login_response, cmd, file_name)
                broadcast(message, cl_sock)

            except:
                break

        cl_sock.close()
        if cl_sock in clients:
            clients.remove(cl_sock)


def server_entrypoint():
    serv_soc = socket.socket()
    serv_soc.bind(('localhost', 9090))
    print("socket created and bind with ip address(localhost) at port 9090 \n")
    serv_soc.listen(3)
    GloblaVariableGeneration.genPandG()  # generate p, g deffie hellman ka every time, when server is online

    while True:
        cl_sock, addr = serv_soc.accept()
        cl_thread = threading.Thread(target=handling_client, args=(cl_sock, addr))
        cl_thread.start()


if __name__ == "__main__":
    server_entrypoint()