# python3.6

import json
import random
import time
from paho.mqtt import client as mqtt_client
import mysql.connector

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

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="dataTugasakhir"
)


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


def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        data = json.loads(msg.payload.decode())
        dekripsiRSA(data['dataEnkripsiRSA'], data['privateKeyRSA'])
        # print(data['privateKey'])
        # print(data['dataEnkripsiRSA'])
        # print(type(data['dataEnkripsiRSA']))
        # dekripsiRSA(data['dataEnkripsiRSA'])
        # print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")

    client.subscribe(topic)
    client.on_message = on_message
def dekripsiRSA(dataEnkripsi, key):
    RSAprivateKey = RSA.importKey(ast.literal_eval(key))
    OAEP_cipher = PKCS1_OAEP.new(RSAprivateKey)
    decryptedMsg1 = OAEP_cipher.decrypt(ast.literal_eval(dataEnkripsi))
    print('Decryption RSA:', decryptedMsg1.decode('utf-8')) 

    print(type(dataEnkripsi))
    print(type(decryptedMsg1.decode('utf-8')))
    inserData(dataEnkripsi,decryptedMsg1.decode('utf-8'))

def dekripsiECC(dataEnkripsi, key):
    print(dataEnkripsi)
    # decryptedMsg = decrypt_ECC(ast.literal_eval(dataEnkripsi), int(key))
    # print("decrypted ECC:", decryptedMsg)
    

def inserData(encryptData, decryptData):
    sql = "INSERT INTO rsadata (encryptData, decryptData) VALUES (%s, %s)"
    val = (encryptData, decryptData)
    mycursor = mydb.cursor()
    mycursor.execute(sql, val)
    mydb.commit()

    print(mycursor.rowcount, "record inserted.")

def run():
    client = connect_mqtt()
    subscribe(client)
    client.loop_forever()


if __name__ == '__main__':
    run()












