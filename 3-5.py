#set1_5
def Repeating_key_XOR(_message,_key) :
    cipher = b''
    length = len(_key)
    for i in range(0,len(_message)) :
        cipher = cipher + bytes([_message[i]^_key[i % length]])
        # print(cipher.hex())
    return cipher

if __name__ == '__main__' :
    message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    ciphertext = Repeating_key_XOR(message,key)
    print(ciphertext.hex())
