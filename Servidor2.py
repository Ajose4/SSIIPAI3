# coding=utf-8
import datetime
import hashlib
import socket

# ------------------------------------------------
#clave que vamos a utilizar, se debe proporcionar al cliente y debe estar guardada en el servidor.
#en la variable secuencia vamos a ir guardando la secuencia de los mensajes que nos vayan llegando, asi
#verificaremos con otro metodo auxiliar que no llega ningun mensaje con numero de secuencia duplicado, evita ataque replay
#las variables MensajesCorruptos y MensajesTotales nos ayudaran a calcular el % de corrupcion de los mensajes.
clave = "clave"
puerto = 10000
carpetaLogs = "C://Users//juan1//Desktop//SSII-P2//Logs//"
secuencias = []
MensajesCorruptos = 0
MensajesTotales = 0

# ------------------------------------------------

#funcion auzxiliar para hashing
def auxiliar(mensaje,sec,opcion):
    var = mensaje + clave + sec
    hashing=""
    if (opcion=="SHA"):
        hashing = hashlib.sha256()
    if (opcion=="MD5"):
        hashing = hashlib.md5()
    hashing.update(var.encode('utf-8'))
    return hashing.hexdigest()

#definir funcion auxiliar2 para prevenir ataque de replay. Comprobamos que el numero de secuencia del mensaje
#recibido no este duplicado.

def auxiliar2(sec):
    var = False
    if sec not in secuencias:
        secuencias.append(sec)
        var = True
    return var

# funciones de creacion de "Logs"

def creaLogError(socket,mensaje,hashing,sec):

    ahora = datetime.datetime.now().strftime("%Y-%m-%d, (%H-%M-%S)")
    ahora2 = datetime.datetime.now().strftime("%Y-%m-%d, (%H:%M:%S)")
    archiv = carpetaLogs+ahora+".txt"
    archivo=open(archiv,'w')
    archivo.write('Error en la comprobación, posible ataque detectado.\n')
    archivo.write('Socket= '+socket+'\n')
    archivo.write('Mensaje= '+mensaje+'\n')
    archivo.write('Hashing= '+hashing+'\n')
    archivo.write('Secuencia= '+sec+'\n')
    archivo.write('KPI= '+ str((MensajesCorruptos/MensajesTotales)*100)+'% \n')
    archivo.write('Fecha = ' + ahora2)
    archivo.close()
    # nota: ahora y ahora2 es debido a que windows no permite poner ":" en el nombre 
    # de un archivo
    
def creaLog(socket,mensaje,sec):

    ahora = datetime.datetime.now().strftime("%Y-%m-%d, (%H-%M-%S)")
    ahora2 = datetime.datetime.now().strftime("%Y-%m-%d, (%H:%M:%S)")
    archiv = carpetaLogs+ahora+".txt"
    archivo=open(archiv,'w')
    archivo.write('Mensaje recibido correctamente.\n')
    archivo.write('Socket= '+socket+'\n')
    archivo.write('Mensaje= '+mensaje+'\n')
    archivo.write('Secuencia= '+sec+'\n')
    archivo.write('KPI= '+ str((MensajesCorruptos/MensajesTotales)*100)+'% \n')
    archivo.write('Fecha = ' + ahora2)
    archivo.close()

#diferentes mensajes que enviamos de respuesta al cliente segun si la transferencia se realiza correctamente.
def enviarMensaje(ip, puerto):
    sock = socket.socket()
    sock.connect((ip, puerto))
    men = "Transferencia realizada correctamente"
    MVar= men
    sock.send(bytes(MVar))

def enviarMensaje2(ip, puerto):
    socki = socket.socket()
    socki.connect((ip, puerto))
    mend = "Transferencia fallida, vuelva a intentarlo"
    MVarf= mend
    socki.send(bytes(MVarf))

# Creando el socket para la llegada por parte de cliente manteniendo la espera de conexion activada.
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', puerto)
sock.bind(server_address)
sock.listen(5)
while True:
    print ('Esperando conexion:')
 
    while True:
        connection, client_address = sock.accept()
        data = connection.recv(500)
        if data:
            mensaje= data.decode("utf-8").split(",,,,,")
            varReplay = auxiliar2(mensaje[2])
            if (mensaje[1]==auxiliar(mensaje[0],mensaje[2],"SHA") or mensaje[1]==auxiliar(mensaje[0],mensaje[2],"MD5")) and varReplay:
                print ("Mensaje recibido de la siguiente ip: " + str(client_address))
                print ("Mensaje: " + mensaje[0])
                print ("\n ----------------------------- \n")
                print ('Esperando nueva conexion:')
                data=None
                MensajesTotales = MensajesTotales + 1
                creaLog(str(client_address),mensaje[0],mensaje[2])
                enviarMensaje('localhost',10001)

            else:
                print ("Mensaje recibido de la siguiente ip: " + str(client_address))
                print ("\nDETECTADO INTENTO DE SUPLANTACION, SE ELIMINARÁ EL MENSAJE")
                print ("\n ----------------------------- \n")
                print ('Esperando nueva conexion:')
                MensajesTotales = MensajesTotales + 1
                MensajesCorruptos = MensajesCorruptos + 1
                data=None
                creaLogError(str(client_address),mensaje[0],mensaje[1],mensaje[2])
                enviarMensaje2('localhost', 10001)


            
            
