from os import add_dll_directory, remove, urandom, path
add_dll_directory(path.dirname(__file__)+"\\libs")
import socketserver  
import libs.openfhe as ofhe
import sqlite3      
import binascii

DB_NAME = "Data.db"
LENGTH = 20
TOTAL = 125

logined_user= {}

class database():
    def __init__(self, DBname):
        self.con = sqlite3.connect(DBname)
        self.cur = self.con.cursor()

    def NewUser(self, name, context, pubkey, multkey):
        dic = ({"name":name})
        if self.cur.execute(f"SELECT key, value FROM data WHERE user=:name", dic).fetchall() != []:
            return 2
        con, pub = getcontext(context, pubkey, multkey)
        k,v = Emptydata(con, pub)
        dic = ({"name":name ,"key":k,"value":v, "context":context, "pubkey":pubkey, "multkey":multkey})
        self.cur.execute(f"INSERT INTO data VALUES(:name, :context, :pubkey, :multkey, :key, :value)", dic)
        self.con.commit()
        return 0

    def update(self, name, key, value):
        dic = ({"name":name ,"key":key,"value":value})
        self.cur.execute(f"UPDATE data SET key=:key,value=:value WHERE user=:name", dic)
        self.con.commit()

    def getdata(self, name):
        dic = ({"name":name})
        return self.cur.execute(f"SELECT context, pubkey, multkey, key, value FROM data WHERE user=:name", dic).fetchall()[0]
    
    def close(self):
        self.con.close()

class accountDB():
    def __init__(self, DBname):
        self.con = sqlite3.connect(DBname)
        self.cur = self.con.cursor()
    def Gentoken(self):
        t = binascii.hexlify(urandom(5))
        while (b'00' in t or t in logined_user):
            t = binascii.hexlify(urandom(5))
        return t
    def register(self, name, password):
        dic = ({"name":name ,"pass":password})
        if self.cur.execute(f"SELECT password FROM Account WHERE user=:name", dic).fetchall() != []:
            return 0
        self.cur.execute(f"INSERT INTO Account VALUES(:name, :pass)", dic)
        self.con.commit()
        return 1
    def check_valid(self, name, password):
        dic = ({"name":name})
        Cpass = self.cur.execute(f"SELECT password FROM Account WHERE user=:name", dic).fetchall()[0]
        if Cpass == []:
            return 0
        if (password) == Cpass[0]:
            return 1
        else:
            return 0

    def login(self, name, password):
        dic = ({"name":name})
        if self.check_valid(name, password):
            token = self.Gentoken()
            logined_user[token] = name
        else:
            token = b'000'
        return token
    def logout(self, token):
        del logined_user[token]
        return
    def modify_user(self, name, password):
        dic = ({"name":name ,"pass":password})
        self.cur.execute(f"UPDATE Account SET password=:pass WHERE user=:name", dic)
        self.con.commit()

    def close(self):
        self.con.close()

def initDB():
    if not path.isfile("Data.db"):
        con = sqlite3.connect(DB_NAME)
        cur = con.cursor()
        cur.execute(f"CREATE TABLE Account(user, password)")
        cur.execute(f"CREATE TABLE data(user, context, pubkey, multkey, key, value)")
        con.close()

def getcontext(cont, pub, mult):
    with open("temp", 'wb') as tmp:
        tmp.write(cont)
    context, result = ofhe.DeserializeCryptoContext( "temp", ofhe.BINARY)
    remove("temp")
    with open("temp", 'wb') as tmp:
        tmp.write(mult)
    context.DeserializeEvalMultKey("temp", ofhe.BINARY)
    remove("temp")
    with open("temp", 'wb') as tmp:
        tmp.write(pub)
    public_key, result = ofhe.DeserializePublicKey("temp", ofhe.BINARY)
    remove("temp")
    return (context, public_key)

def Serialize(data):
    ofhe.SerializeToFile("temp", data, ofhe.BINARY)
    with open("temp","rb") as f:
        b = f.read()
    remove("temp")
    return b

def Deserialize(context, public_key, data, type):
    if len(data) == 0:
        return context.Encrypt(public_key, context.MakePackedPlaintext([0]))

    with open('temp',"wb") as f:
        f.write(data)
    if type == "CText":
        ct, res = ofhe.DeserializeCiphertext("temp",ofhe.BINARY)
    remove("temp")
    return ct
    
def Emptydata(context, public_key):
    k = Serialize(context.Encrypt(public_key,context.MakePackedPlaintext([0]*TOTAL)))+str(0).encode().zfill(10)
    v = Serialize(context.Encrypt(public_key,context.MakePackedPlaintext([0]*LENGTH*TOTAL)))
    return k, v

def load(name, db):
    con, pubkey, multkey, Keydata, Valuedata = db.getdata(name)
    size = int(Keydata[-10:].strip())
    Keydata = Keydata[:-10]
    context, public_key = getcontext(con, pubkey, multkey)
    return Keydata, Valuedata, size, context, public_key


def save(name, Keydata, Valuedata, size, db):
    Keydata += str(size).encode().zfill(10)
    db.update(name, Keydata, Valuedata)


def formatlist(size,key:bool):
    if key:
        return [0]*(size)+[1]+[0]*(TOTAL-size-1)
    else:
        return [0]*(size*LENGTH)+[1]*LENGTH+[0]*(TOTAL-size-1)*LENGTH



class TCPHandler(socketserver.BaseRequestHandler):

    def getalldata(self):
        package = self.request.recv(4096)
        data_size = package[:10].strip()
        data = package[10:]
        while len(data) < int(data_size):
            package = self.request.recv(4096)
            if not package:
                break
            data = data + package
        return data

    def senddata(self, data):
        self.request.sendall(str(len(data)).encode().zfill(10)+data)
        return 0;

    def handle(self):
        db = database(DB_NAME)
        Adb = accountDB(DB_NAME)
        query = self.getalldata()
        if query == b'connecttest':
            self.senddata(b'1')
            return
        if query == b'removeall':
            db.close()
            Adb.close()
            remove(DB_NAME)
            initDB()
            return
        operate = query[:1]
        key = query[1:]
        user = 0
        #operate 1:search 2:add 3:register 4:login
        if operate == b'1' or operate == b'2':
            token, key = key.split(b"@@@@")
            if token in logined_user:
                user = logined_user[token]
                Keydata, Valuedata, size, context, public_key = load(user, db)
            else:
                self.senddata(b'001') #Invalid token
                return
        if operate == b'1':
            if size == 0:
                self.senddata(b'000')
                return
            key = Deserialize(context, public_key, key, "CText")
            key = context.EvalMult(key, context.MakePackedPlaintext([-1]*LENGTH))
            result = context.EvalAdd(Deserialize(context, public_key, Keydata, "CText"),key)
            self.senddata(Serialize(result))
            received = self.getalldata()
            received = Deserialize(context, public_key, received,"CText")
            result = context.EvalMult(Deserialize(context, public_key, Valuedata, "CText"), received)
            self.senddata(Valuedata)
        #add_data
        elif operate == b'2':
            self.senddata(str(size).encode())#need value
            value = self.getalldata()
            Keydata = Serialize(context.EvalAdd(Deserialize(context, public_key, Keydata,"CText"),context.EvalMult(Deserialize(context, public_key, key,"CText"),context.MakePackedPlaintext(formatlist(size,1)))))
            Valuedata = Serialize(context.EvalAdd(Deserialize(context, public_key, Valuedata,"CText"),context.EvalMult(Deserialize(context, public_key, value,"CText"),context.MakePackedPlaintext(formatlist(size,0)))))
            size+=1
            self.senddata(b'0') #Done
        elif operate == b'3': #register
            username, value = key.split(b"@@@@")
            self.senddata(b'1')
            con = self.getalldata()
            if con:
                self.senddata(b'1')
                pub = self.getalldata()
                if pub:
                    self.senddata(b'1')
                    mult = self.getalldata()
                    if mult:
                        if db.NewUser(username, con, pub, mult) == 0:
                            Adb.register(username, value)
                            self.senddata(b'1')
                            return
                        else:
                            self.senddata(b'000')
                            return
                            
        elif operate == b'4': #login
            username, value = key.split(b"@@@@")
            token = Adb.login(username, value)

            self.senddata(token)
            return
        elif operate == b'5': #logout
            Adb.logout(key)
            #self.senddata(b'1')
            return
        if user:
            save(user, Keydata, Valuedata, size, db)
        db.close()
        Adb.close()

if __name__ == "__main__":
    HOST, PORT = "localhost", 30087
    initDB()
    with socketserver.ThreadingTCPServer(("", PORT), TCPHandler) as server:
        print("Server running...")
        server.serve_forever()



