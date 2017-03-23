import socket
import hashlib
import random
import ssl

try:
    # for Python2
    import tkinter as tk   ## notice capitalized T in Tkinter 
except ImportError:
    # for Python3
    import tkinter as tk

#variables
key = "C://Users//Fran//Desktop//SSII-P3//v1//key y certificado//server.key"
cert = "C://Users//Fran//Desktop//SSII-P3//v1//key y certificado//server.crt"
ip="localhost"
puerto=10000
    
#funcion auxiliar
def aux(mensaje,user,contraseña,algoritmo,clave):
    
    socket = abrirSocket(ip,puerto)
    secuencia = random.randint(0, 999999999999999999)
    enviarMensaje(mensaje,socket,algoritmo,clave,str(secuencia),user,contraseña)

# utilizando SSl
def abrirSocket(ip,puerto):
    sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslContext.load_dh_params("dhparam.pem")
    ssl_sock=ssl.wrap_socket(socket.socket(), 
                                 ca_certs=cert, 
                                 cert_reqs=ssl.CERT_REQUIRED,
                                 server_side=False,
                                 do_handshake_on_connect=True,
                                 ciphers = "ECDHE-RSA-AES256-SHA384")
    ssl_sock.connect((ip,puerto))
    return ssl_sock
    
def enviarMensaje(mensaje,socket,algoritmo,password,secuencia,user,contraseña):
    mensajeypass = mensaje + password + secuencia + user + contraseña
    hashing=""
    if (algoritmo=="SHA"):
        hashing = hashlib.sha256()
    if (algoritmo=="MD5"):
        hashing = hashlib.md5()
    hashing.update(mensajeypass.encode('utf-8'))
    MVar= mensaje+",,,,,"+str(hashing.hexdigest()+",,,,,"+secuencia+",,,,,"+user+",,,,,"+contraseña)
    socket.send(bytes(MVar, 'utf-8'))
    respuesta = socket.recv(1024)
    print(respuesta.decode('utf-8'))
    socket.close()


class SampleApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Datos para enviar: mensaje, usuario(user), pass(user), algoritmo(MD5 o SHA) y password(clave).")
        self.geometry('900x200+200+200')
  
        self.entry = tk.Entry(self)
        self.entry2 = tk.Entry(self)
        self.entry3 = tk.Entry(self)
        self.entry4 = tk.Entry(self)
        self.entry5 = tk.Entry(self)
        self.button = tk.Button(self, text="Enviar", command=self.on_button,bg='red')
        self.entry.pack()
        self.entry2.pack()
        self.entry3.pack()
        self.entry4.pack()
        self.entry5.pack()
        self.button.pack()


    def on_button(self):
        aux(self.entry.get(),self.entry2.get(),self.entry3.get(),self.entry4.get(),self.entry5.get())

app = SampleApp()
app.mainloop()
    
