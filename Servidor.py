import socket
import hashlib
import datetime
import ssl

# ------------------------------------------------

clave = "clave"
puerto = 10000
ip="localhost"
carpetaLogs = "C://Users//Fran//Desktop//SSII-P3//Logs//"
secuencias = []
MensajesCorruptos = 0
MensajesTotales = 0

key = "C://Users//Fran//Desktop//SSII-P3//key y certificado//server.key"
cert = "C://Users//Fran//Desktop//SSII-P3//key y certificado//server.crt"

usuarios = []
usuarios.append("user-user")

# ------------------------------------------------

#definir funcion auzxiliar para hashing
def auxiliar(string,sec,user,contraseña,opcion):
    var = string + clave + sec + user + contraseña
    hashing=""
    if (opcion=="SHA"):
        hashing = hashlib.sha256()
    if (opcion=="MD5"):
        hashing = hashlib.md5()
    hashing.update(var.encode('utf-8'))
    return hashing.hexdigest()

#definir funcion auxiliar2 para prevenir ataque de replay

def auxiliar2(sec):
    var = False
    if sec not in secuencias:
        secuencias.append(sec)
        var = True
    return var

# funciones de creacion de "Logs"

def creaLogError(socket,mensaje,hashing,sec,usuario,contraseña):

    ahora = datetime.datetime.now().strftime("%Y-%m-%d, (%H-%M-%S)")
    ahora2 = datetime.datetime.now().strftime("%Y-%m-%d, (%H:%M:%S)")
    archiv = carpetaLogs+ahora+".txt"
    archivo=open(archiv,'w')
    archivo.write('Error en la comprobación, posible ataque detectado.\n')
    archivo.write('Socket= '+socket+'\n')
    archivo.write('Usuario= '+usuario+'\n')
    archivo.write('Contraseña= '+contraseña+'\n')
    archivo.write('Mensaje= '+mensaje+'\n')
    archivo.write('Hashing= '+hashing+'\n')
    archivo.write('Secuencia= '+sec+'\n')
    archivo.write('KPI= '+ str((MensajesCorruptos/MensajesTotales)*100)+'% \n')
    archivo.write('Fecha = ' + ahora2)
    archivo.close()
    # nota: ahora y ahora2 es debido a que windows no permite poner ":" en el nombre 
    # de un archivo
    
def creaLog(socket,mensaje,sec,usuario,contraseña):
    ahora = datetime.datetime.now().strftime("%Y-%m-%d, (%H-%M-%S)")
    ahora2 = datetime.datetime.now().strftime("%Y-%m-%d, (%H:%M:%S)")
    archiv = carpetaLogs+ahora+".txt"
    archivo=open(archiv,'w')
    archivo.write('Mensaje recibido correctamente.\n')
    archivo.write('Socket= '+socket+'\n')
    archivo.write('Usuario= '+usuario+'\n')
    archivo.write('Contraseña= '+contraseña+'\n')
    archivo.write('Mensaje= '+mensaje+'\n')
    archivo.write('Secuencia= '+sec+'\n')
    archivo.write('KPI= '+ str((MensajesCorruptos/MensajesTotales)*100)+'% \n')
    archivo.write('Fecha = ' + ahora2)
    archivo.close()
 
# Creando el socket TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (ip, puerto)
sock.bind(server_address)
sock.listen(5)
while True:
    print ('Esperando conexion:')
    
    while True:
        connection, client_address = sock.accept()
        sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslContext.load_dh_params("dhparam.pem") # importante cargar esta libreria en carpeta de usuario
        connstream = ssl.wrap_socket(connection, 
                                 server_side=True, 
                                 keyfile=key,
                                 certfile=cert, 
                                 ciphers = "ECDHE-RSA-AES256-SHA384")
        data = connstream.read()
        
        if data:
            mensaje= data.decode("utf-8").split(",,,,,")
            varReplay = auxiliar2(mensaje[2])
            if (mensaje[1]==auxiliar(mensaje[0],mensaje[2],mensaje[3],mensaje[4],"SHA")
                or mensaje[1]==auxiliar(mensaje[0],mensaje[2],mensaje[3],mensaje[4],"MD5")) and varReplay:
                if(mensaje[3]+"-"+mensaje[4] not in usuarios):
                    connstream.send(("Usuario y contraseña incorrectos.").encode("utf-8"))
                else:
                    print ("Mensaje recivido de la siguiente ip: " + str(client_address))
                    print ("Mensaje: " + mensaje[0])
                    print ("\n ----------------------------- \n")
                    print ('Esperando nueva conexion:')
                    data=None
                    MensajesTotales = MensajesTotales + 1
                    creaLog(str(client_address),mensaje[0],mensaje[2],mensaje[3],mensaje[4])
                    connstream.send(("Identificación correcta.").encode("utf-8"))
            else:
                print ("Mensaje recivido de la siguiente ip: " + str(client_address))
                print ("\nDETECTADO INTENTO DE SUPLANTACION, SE ELIMINARÁ EL MENSAJE")
                print ("\n ----------------------------- \n")
                print ('Esperando nueva conexion:')
                MensajesTotales = MensajesTotales + 1
                MensajesCorruptos = MensajesCorruptos + 1
                data=None
                creaLogError(str(client_address),mensaje[0],mensaje[1],mensaje[2],mensaje[3],mensaje[4])
                connstream.send(("Detectado ataque, se generará informe ...").encode("utf-8"))


            
            
