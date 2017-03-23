import socket
import hashlib
import random
import Tkinter

#funcion auxiliar
def aux(mensaje,ip,puerto,algoritmo,password):
    
    socket = abrirSocket(ip,puerto)
    secuencia = random.randint(0, 999999999999999999)
    enviarMensaje(mensaje,socket,algoritmo,password,str(secuencia).encode("utf-8"))

# utilizando SSl
def abrirSocket(ip,puerto):
    sock = socket.socket()
    sock.connect((ip,puerto))
    return sock

#Funcion para enviar el mensaje segun el tipo de algoritmo. Mandamos el mensaje, el hashing y la secuencia.
def enviarMensaje(mensaje,socket,algoritmo,password,secuencia):
    mensajeypass = mensaje + password + secuencia
    hashing=""
    if (algoritmo=="SHA"):
        hashing = hashlib.sha256()
    if (algoritmo=="MD5"):
        hashing = hashlib.md5()
    hashing.update(mensajeypass.encode('utf-8'))
    MVar= mensaje+",,,,,"+str(hashing.hexdigest()+",,,,,"+secuencia)
    socket.send(bytes(MVar))

#Funcion interfaz para introducir los datos.
class Interfaz(Tkinter.Tk):
    def __init__(self):
        Tkinter.Tk.__init__(self)
        self.title("Datos para enviar: mensaje, ip(localhost), puerto(10000), algoritmo(MD5 o SHA) y password(clave).")
        self.geometry('900x200+200+200')
  
        self.entry = Tkinter.Entry(self)
        self.entry2 = Tkinter.Entry(self)
        self.entry3 = Tkinter.Entry(self)
        self.entry4 = Tkinter.Entry(self)
        self.entry5 = Tkinter.Entry(self)
        self.button = Tkinter.Button(self, text="Enviar", command=self.on_button,bg="blue")
        self.entry.pack()
        self.entry2.pack()
        self.entry3.pack()
        self.entry4.pack()
        self.entry5.pack()
        self.button.pack()

#for i in range (1,100):
 #   aux("mensaje", 'localhost', 10000, "SHA", "clave")


    def on_button(self):
        aux(self.entry.get(),self.entry2.get(),int(self.entry3.get()),self.entry4.get(),self.entry5.get())

app = Interfaz()
app.mainloop()

#abrimos un socket para escuchar una posible respuesta del servidor
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10001)
sock.bind(server_address)
sock.listen(5)
while True:
    print ('Esperando respuesta:')
    while True:
        connection, client_address = sock.accept()
        data = connection.recv(500)
        mensaje = data.decode("utf-8")
        print(mensaje)

