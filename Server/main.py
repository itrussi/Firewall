import socket
from hashtable import *
import ast

HOST = socket.gethostname()
PORT = 8080

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

server.listen(1)

class responseHandler:
    
    def __init__(self):
        self.table = HashTable(1000)
    
    def insert(self, type, item, reason):
        
        #Save to CSV

        # Inserts the dictionary
        return "Success"
    
    def search(self, data):
        return "Search CSV"
    
    def update(self, data):
        
        #Update a CSV file
        
        return "Data succcessfully updated"

def authenticate(client, table):
    client.send('UNAME'.encode('utf-8'))
    username = client.recv(1024).decode('utf-8')

    results = table.search(username)
    if username == results['Username']:
        fetched_password = results['Password']
        client.send('PSWD'.encode('utf-8'))
        password = client.recv(1024).decode('utf-8')
        if password != fetched_password:
            client.send('REFUSE'.encode('utf-8'))
            client.close()
        
    if results != "Username not found":
        client.send('REFUSE'.encode('utf-8'))
        client.close()
    
while True:
    responseHandler1 = responseHandler()
    
    communication_socket, addr = server.accept()
    print(f"Server connected to: {addr}")

    authenticate(communication_socket)

    try:
        message = communication_socket.recv(1024).decode('utf-8')
        print(f"Message from client is: {message}")
        
        x = message.split(", ")
        
        first = x[0]
        
        if x[0] == "Ban Port":
            
            port = x[1]
            reason = x[2]
            type = "Port"
        
            response = responseHandler1.insert(type, port, reason)
        elif x[0] == "Ban IP":
        
            ip = x[1]
            reason = x[2]
            type = "IP"
        
            response = responseHandler1.insert(type, ip, reason)
            
        elif x[0] == "Ban URL":
            
            url = x[1]
            reason = x[2]
            type = "URL"
        
            response = responseHandler1.insert(url, reason)
    
        elif x[0] == "Unban Port":
            
            port = x[1]
            reason = x[2]
            type = "Port"
        
            response = responseHandler1.delete(type, port, reason)
    
        elif x[0] == "Unban IP":
            
            ip = x[1]
            reason = x[2]
            type = "IP"
        
            response = responseHandler1.delete(type, ip, reason)
    
        elif x[0] == "Unban URL":
            
            url = x[1]
            reason = x[2]
            type = "URL"
        
            response = responseHandler1.delete(type, url, reason)

        else:
            # Broadcast
            pass
    
        communication_socket.send(f"{response}".encode('utf-8'))
        communication_socket.close()
        print(f"Communication with {addr} closed")

    except:
        continue
