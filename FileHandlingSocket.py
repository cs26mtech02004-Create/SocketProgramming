import os
import my_enc_decrp as ENC_DECRP

def filemgmtcommand(cmd, dh_secretkey, reqd_filename=None):
    if cmd == "LIST":
        print("--- Directory Listing ---")
        lists = []
        for file in os.listdir("./"):
            lists.append(file)
        print(lists)
        list_str = " ".join(lists) #list ko str m convert karna
        print("list sent", list_str)
        return ENC_DECRP.aes_encrypt(list_str.encode(), dh_secretkey)

    if cmd not in ("GET", "INFO", "SIZE","LIST"):
        return ENC_DECRP.aes_encrypt("UNKNOWN_COMMAND".encode(), dh_secretkey)

    if not reqd_filename or not os.path.exists(reqd_filename):
        print(f"Error: File '{reqd_filename}' not found.")
        return ENC_DECRP.aes_encrypt("file not found".encode(), dh_secretkey)

    match cmd:
        case "GET":
            seq_no = 0
            packets = []
            print(f"--- Content of {reqd_filename} ---")
            with open(reqd_filename, "rb") as f:
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    cipher_data = ENC_DECRP.aes_encrypt(chunk, dh_secretkey)
                    mac = ENC_DECRP.compute_mac(cipher_data, seq_no, dh_secretkey)
                    header = f"{seq_no}|{len(cipher_data)}|\n".encode()
                    packet = header + cipher_data + mac
                    packets.append(packet)
                    seq_no += 1
                packets.append(b"EOF")
            print("chunks sended from filemgmtcommand")
            return packets

        case "INFO":
            print(f"--- Stats for {reqd_filename} ---")
            info = str(os.stat(reqd_filename)).encode()
            return ENC_DECRP.aes_encrypt(info, dh_secretkey)

        case "SIZE":
            size = os.stat(reqd_filename).st_size
            sizeinfo = f"File size: {size} bytes".encode()
            return ENC_DECRP.aes_encrypt(sizeinfo, dh_secretkey) #send kiya encyption byte data server ko



# print(filemgmtcommand("LI","credentials.txt"))