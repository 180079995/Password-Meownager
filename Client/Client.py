from os import add_dll_directory, remove, path, mkdir
add_dll_directory(path.dirname(__file__)+"\\libs")
import socket
import libs.openfhe as ofhe
import hashlib as hl

import asyncio
import websockets

HOST, PORT = "localhost", 30087

secret = "/secretkey"
public = "/publickey"
context_name = "/context"
mult = "/multkey"
foldername = "keys"
LENGTH = 20
TOTAL= 125

def keygen():
    serType = ofhe.BINARY
    if path.exists(foldername+secret):
        return
    if not path.isdir(foldername):
        mkdir(foldername)
    parameters = ofhe.CCParamsBFVRNS()
    parameters.SetPlaintextModulus(99483649)
    parameters.SetMultiplicativeDepth(8)
    crypto_context = ofhe.GenCryptoContext(parameters)
    crypto_context.Enable(ofhe.PKESchemeFeature.PKE)
    crypto_context.Enable(ofhe.PKESchemeFeature.KEYSWITCH)
    crypto_context.Enable(ofhe.PKESchemeFeature.LEVELEDSHE)
    keypair = crypto_context.KeyGen()
    crypto_context.EvalMultKeyGen(keypair.secretKey)
    ofhe.SerializeToFile(foldername + secret, keypair.secretKey, serType)
    ofhe.SerializeToFile(foldername + public, keypair.publicKey, serType)
    ofhe.SerializeToFile(foldername + context_name, crypto_context, serType)
    crypto_context.SerializeEvalMultKey(foldername + mult, serType)

def str2num(string, is_key:bool, size = 0):#if is_key, it will get hashed
    if is_key:
        numlist = [int.from_bytes(hl.shake_256(string.encode('utf-8')).digest(3), byteorder='little')]*TOTAL
    else:
        num = str(int.from_bytes(string.encode('utf-8'), 'little'))
        numlist = [int(num[:len(num)%5])]+[int(num[i:i+5]) for i in range(len(num)%5,len(num),5)]
        while len(numlist)<LENGTH:
            numlist = [0]+numlist
        numlist = [0]*(size*LENGTH)+numlist+[0]*(TOTAL-size-1)*LENGTH
    return numlist

def num2str(data):
    integer = int("".join([str(i).zfill(5) for i in data]))
    #print(integer)
    #integer = round(integer)
    #print(integer)
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'little').decode('utf-8')

def Serialize(data):
    ofhe.SerializeToFile("temp", data, ofhe.BINARY)
    with open("temp","rb") as f:
        b = f.read()
    remove("temp")
    return b

def Deserialize(data, type):
    if type == 'CText':
        with open('temp',"wb") as f:
            f.write(data)
        ct, res = ofhe.DeserializeCiphertext("temp",ofhe.BINARY)
        remove("temp")
        return ct


def unpack(PlainText:ofhe.Plaintext):
    return [int(i) for i in str(PlainText)[1:-5].split()]

def encrypt(data:list, context, public_key):
    text = context.MakePackedPlaintext(data)
    data_encrypted = context.Encrypt(public_key, text)
    return Serialize(data_encrypted)

def decrypt(data, context, secret_key):
    data = context.Decrypt(secret_key ,data)
    return [int(i) for i in str(data)[1:-5].split()]

def senddata(socket, data):
    socket.sendall(str(len(data)).encode().zfill(10)+data)
    return 0

def getalldata(socket):
        package = socket.recv(4096)
        data_size = package[:10].strip()
        data = package[10:]
        while len(data) < int(data_size):
            package = socket.recv(4096)
            if not package:
                break
            data = data + package
        return data

def DataTransfer(socket, data):
    senddata(socket, data)
    received = getalldata(socket)
    return received

def confirm():
    pass
    return 1

def add(key, value, token):
    context, result = ofhe.DeserializeCryptoContext(foldername + context_name, ofhe.BINARY)
    public_key, result = ofhe.DeserializePublicKey(foldername + public, ofhe.BINARY)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        key = encrypt(str2num(key, True), context, public_key)
        size =  DataTransfer(sock, b'2'+token+b'@@@@'+key)
        if size == b'001':
            return "Invalid token"
        else:
            size = int(size)
        value = encrypt(str2num(value, False , size = size), context, public_key)
        if DataTransfer(sock, value) == b'0':
            return "Done"
        else:
            return "Error"

def search(key, token):
    context, result = ofhe.DeserializeCryptoContext(foldername + context_name, ofhe.BINARY)
    public_key, result = ofhe.DeserializePublicKey(foldername + public, ofhe.BINARY)
    secret_key, result = ofhe.DeserializePrivateKey(foldername + secret, ofhe.BINARY)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        key = encrypt(str2num(key, True), context, public_key)
        received = DataTransfer(sock, b'1'+token+b'@@@@'+key)
        
        if received == b'000':
            return "No Data found"
        if received == b'001':
            return "Invalid token"
        result = [int(not i) for i in decrypt(Deserialize(received, "CText"), context, secret_key)]
        result2 = []
        for i in result:
            if i:
                result2+=[1]*LENGTH
            else:
                result2+=[0]*LENGTH
        received = DataTransfer(sock, encrypt(result2, context, public_key))

        received2 = context.EvalMult(Deserialize(received, "CText"), context.MakePackedPlaintext(result2))
        
        decrypted = decrypt(received2 , context, secret_key)
        #print(decrypted)
        if sum(decrypted) == 0:
            return "No data found"
        decrypted = [decrypted[i:i+LENGTH] for i in range(0,TOTAL,LENGTH)]
    ''' results = []
    for j in [i for i in decrypted if sum(i) != 0]:
        results.append(num2str(j))
    return "@@@@".join(results)'''
    return (num2str([i for i in decrypted if sum(i) != 0][-1]))

def register(username, password):
    password = hl.sha256(password.encode()).hexdigest()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        if DataTransfer(sock, b'3'+username.encode()+b'@@@@'+password.encode()) == b'1':
            with open(foldername+context_name,"rb") as f:
                con = f.read()
            if DataTransfer(sock,con) == b'1':
                with open(foldername+public,"rb") as f:
                    pub = f.read()
                if DataTransfer(sock,pub) == b'1':
                    with open(foldername+mult,"rb") as f:
                        mul = f.read()
                    if DataTransfer(sock,mul) == b'1':
                        return 1
                    else:
                        return 0
        return 0
    
def login(username, password):
    password = hl.sha256(password.encode()).hexdigest()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        t = DataTransfer(sock, b'4'+username.encode()+b'@@@@'+password.encode())
        #print(t)
        if t != b'000':
            return t
        else:
            return 0

def logout(token):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        if DataTransfer(sock, b'5'+token) == b'1':
            return 1
        else:
            return 0

token = 0
async def handle_connection(websocket, path):
    global token
    try:
        async for message in websocket:
            #print(f"Received message: {message}")
            operate = message[:5]
            if operate == "state":
                if token:
                    response = "5@@@@1"
                else:
                    response = "5@@@@0"
            elif operate == "login":
                response = '0@@@@'
                username, password = message[5:].split("@@@@")
                token = login(username, password)
                if token:
                    r = 1
                else:
                    r = 0
                response += str(r)
            elif operate == "regis":
                username, password = message[5:].split("@@@@")
                response = '1@@@@'
                response += str(register(username, password))
            elif operate == "add__":
                key, value = message[5:].split("@@@@")
                response = '2@@@@'
                #print(key, value)
                result = add(key, value, token)
                if result == "Invalid token":
                    token = 0
                response += result
            elif operate == "searc":
                key = message[5:]
                response = '3@@@@'
                result = search(key, token)
                if result == "Invalid token":
                    token = 0
                response += result
            elif operate == "logou":
                logout(token)
                token = 0
                response = "4@@@@1"
            await websocket.send(response)
    except websockets.exceptions.ConnectionClosedOK:
        print("Closed.")
    except Exception as e:
        print(f"An error occurred: {e}")

    #print(f"Client disconnected from {websocket.remote_address}")

if __name__ == "__main__":
    keygen()
    start_server = websockets.serve(handle_connection, "localhost", 30015)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            if DataTransfer(sock, b'connecttest') == b'1':
                print("Connected to server")
    except:
        print("Can't connect to server.")
        print("Restart to try again.")
        exit()
    print("started...")
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()
