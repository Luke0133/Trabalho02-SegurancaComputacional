from Crypto.Cipher import AES
from Crypto.Util import Counter
import time
import base64

plaintext = "I am Groot."
key = "RandomKeyAES1234"
initialization_vector = b"1010101010101010"

def padding(data: bytes):
    #The length of the pad will be the size of the block (128) subtracted by the remainder of the data size divided by the block size.
    pad_length = AES.block_size - (len(data) % AES.block_size)
    padded_result = data + bytes([pad_length] * pad_length) #Concatenates the data input with the bytes of resulted padding.
    return padded_result

def electronic_codebook(plaintext: str, key: str):
    #Encrypts the plaintext using AES-ECB with the provided key.
    plaintext_bytes = plaintext.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    key_bytes = key.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    cypher = AES.new(key_bytes, AES.MODE_ECB) #Creates the cypher that will be used to encrypt the plaintext.
    padded = padding(plaintext_bytes) #Pads the plaintext to be sure it will be the size of the blocks used in AES.
    cyphertext = cypher.encrypt(padded) #Encrypts the padded plaintext into 128 bits AES with ECB mode.
    return cyphertext

def cipher_block_chaining(plaintext: str, key: str, initialization_vector: bytes):
    #Encrypts the plaintext using AES-CBC with the provided key and initialization vector.
    plaintext_bytes = plaintext.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    key_bytes = key.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    cypher = AES.new(key_bytes, AES.MODE_CBC, initialization_vector) #Creates the cypher that will be used to encrypt the plaintext.
    padded = padding(plaintext_bytes) #Pads the plaintext to be sure it will be the size of the blocks used in AES.
    cyphertext = cypher.encrypt(padded) #Encrypts the padded plaintext into 128 bits AES with CBC mode.
    return cyphertext

def cipher_feedback(plaintext: str, key: str, initialization_vector: bytes):
    #Encrypts the plaintext using AES-CFB with the provided key and initialization vector.
    plaintext_bytes = plaintext.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    key_bytes = key.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    cypher = AES.new(key_bytes, AES.MODE_CFB, initialization_vector) #Creates the cypher that will be used to encrypt the plaintext.
    cyphertext = cypher.encrypt(plaintext_bytes) #Encrypts the plaintext into 128 bits AES with CFB mode.
    return cyphertext

def output_feedback(plaintext: str, key: str, initialization_vector: bytes):
    #Encrypts the plaintext using AES-OFB with the provided key and initialization vector.
    plaintext_bytes = plaintext.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    key_bytes = key.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    cypher = AES.new(key_bytes, AES.MODE_OFB, initialization_vector) #Creates the cypher that will be used to encrypt the plaintext.
    cyphertext = cypher.encrypt(plaintext_bytes) #Encrypts the plaintext into 128 bits AES with OFB mode.
    return cyphertext

def counter(plaintext: str, key: str, initialization_vector: bytes):
    #Encrypts the plaintext using AES-CTR with the provided key and initialization vector (nonce).
    plaintext_bytes = plaintext.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    key_bytes = key.encode('utf-8') #Converts the plaintext to bytes using utf-8 encoding.
    nonce = initialization_vector[:8] #Gets the first 8 bytes of the 16 bytes initialization vector inserted.
    counter = Counter.new(64, prefix=nonce, initial_value=0) #Counter that will be used in the algorithm, in this case, the counter is 128 bits long (64 nonce bits + 64 counter bits).
    cypher = AES.new(key_bytes, AES.MODE_CTR, counter=counter) #Creates the cypher that will be used to encrypt the plaintext.
    cyphertext = cypher.encrypt(plaintext_bytes) #Encrypts the plaintext into 128 bits AES with CTR mode using a 128 bits counter.
    return cyphertext
