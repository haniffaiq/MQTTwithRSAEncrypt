
import json
import random
import time
from paho.mqtt import client as mqtt_client


import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import binascii
import ast
from tinyec import registry
import secrets
from Crypto.Cipher import AES
import hashlib, secrets, binascii


broker = 'broker.hivemq.com'
port = 1883
topic = "data/enkripsi/RSAandECC"
curve = registry.get_curve('brainpoolP256r1')
#Enkripsi ECC
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)
  
def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()



def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


def connect_mqtt():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
        else:
            print("Failed to connect, return code %d\n", rc)

    client = mqtt_client.Client()
    client.on_connect = on_connect
    client.connect(broker, port)
    return client


def publish(client, dataRSA):
    time.sleep(1)
    objData = {
        
        'dataEnkripsiRSA' : dataRSA,
        'privateKeyRSA' : str(privateKey),

    }
    dataJson = json.dumps(objData)
    result = client.publish(topic, dataJson)
    # result: [0, 1]
    status = result[0]
    if status == 0:
        print(f"Send `{dataJson}` to topic `{topic}`")
    else:
        print(f"Failed to send message to topic {topic}")




key = RSA.generate(1024)
privateKey = key.exportKey('PEM')
publicKey = key.publickey().exportKey('PEM') 


msg = input ("Input Data: ") 
msg = str.encode(msg) 

#Enkripsi RSA
RSApublicKey = RSA.importKey(publicKey)
OAEP_cipher = PKCS1_OAEP.new(RSApublicKey)
encryptedMsg1 = OAEP_cipher.encrypt(msg)

print('Encrypted RSA:', encryptedMsg1) 

print("RSA encrypt:", encryptedMsg1)
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

f = open ('encryptionRSA.txt', 'w')
f.write(str(encryptedMsg1)) #write ciphertext to file
f.close()

f = open ('encryptionRSA.txt', 'r')
messageRSA = f.read()


#================================================================================
RSAprivateKey = RSA.importKey(privateKey)
OAEP_cipher = PKCS1_OAEP.new(RSAprivateKey)
decryptedMsg1 = OAEP_cipher.decrypt(ast.literal_eval(str(messageRSA)))

print('Decryption RSA:', decryptedMsg1) 
#================================================================================



# datayang harus dikirim
encryptedMsg = encrypt_ECC(encryptedMsg1, pubKey)
print("Data yang harus dikirim : ", encryptedMsg)

encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted ECC:", encryptedMsgObj)


f = open ('encryptionECC.txt', 'w')
f.write(str(encryptedMsg)) #write ciphertext to file
f.close()

f = open ('encryptionECC.txt', 'r')
messageECC = f.read()

client = connect_mqtt()
publish(client, messageRSA)
    # def run():
    #     client = connect_mqtt()
    #     client.loop_start()
    #     publish(client)
# if __name__ == '__main__':
    # run()
