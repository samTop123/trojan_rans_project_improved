import socket
import ssl
import constants
import string
import os
import hashlib
import base64
import random as rd
import mysql.connector
import mysql.connector.cursor
import db_info

class ServerRans:
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port

    def create_server(self) -> socket.socket:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, self.port))
        server.listen(1)
        return server

    def write_key(self, ip_client: str, word: str) -> bytes:
        # Fernet key: base64-encoded SHA256
        key = base64.urlsafe_b64encode(hashlib.sha256(word.encode()).digest())

        # Save key if not already saved
        if not os.path.exists("keys"):
            os.makedirs("keys")
        if not os.path.exists(f"keys/{ip_client}.key"):
            print("Secret key created!")
            with open(f"keys/{ip_client}.key", "wb") as key_file:
                key_file.write(key)

        return key

    def str_generate(self, size: int) -> str:
        chars = string.ascii_uppercase + string.digits + string.ascii_lowercase + string.punctuation
        return ''.join(rd.choice(chars) for _ in range(size))

    def save_secret_word(self, mycursor: mysql.connector.cursor.MySQLCursor, word: str) -> bool:
        sql_command = f"INSERT INTO {constants.TABLE_NAME} (id, word) VALUES (%s, %s)"
        vals = ("", word)
        mycursor.execute(sql_command, vals)
        print("Saved word to DB.")
        return True

    def send_key(self, ssl_client: ssl.SSLSocket, key: bytes) -> bool:
        try:
            ssl_client.send(key)
            return True
        except Exception as e:
            print("Error sending key:", e)
            return False

    def display_all_in_table(self, mycursor: mysql.connector.cursor.MySQLCursor) -> None:
        sql_command = f"SELECT * FROM {constants.TABLE_NAME}"
        mycursor.execute(sql_command)
        res = mycursor.fetchall()
        print("The words in the table are:")
        for x in res:
            print(x[1])

if __name__ == "__main__":
    server_rans = ServerRans(constants.SERVER_IP, constants.SERVER_PORT)
    server = server_rans.create_server()

    mydb = mysql.connector.connect(user=db_info.user_name, password=db_info.password, host=db_info.host, database='mydatabase')
    my_cursor = mydb.cursor()
    my_cursor.execute(f"USE {constants.DATABASE_NAME}")

    print("The server has been opened ...")

    client, addr = server.accept()
    ssl_client = ssl.wrap_socket(client, server_side=True, certfile="server.crt", keyfile="server.key")
    client_ip, _ = ssl_client.getpeername()

    while True:
        recv_msg = ssl_client.recv(constants.BUFFER_SIZE)
        msg = recv_msg.decode('utf-8')

        if msg == constants.END_CHOICE_NORM:
            print("Server ends ...")
            ssl_client.close()
            break
        elif msg == constants.ATTACK_CHOICE:
            print("Sending the key ATTACK!")

            secret_word = server_rans.str_generate(rd.randint(10, 20))
            server_rans.save_secret_word(my_cursor, secret_word) # type: ignore
            mydb.commit()
            server_rans.display_all_in_table(my_cursor) # type: ignore

            key = server_rans.write_key(client_ip, secret_word)
            server_rans.send_key(ssl_client, key)

    server.close()