def single_byte_xor(text, key):
    return bytes([b ^ key for b in text])

def score_text(text):
    freq = 'etaoin shrdlu'
    return sum(chr(b).lower() in freq for b in text)

hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
cipher = bytes.fromhex(hex_str)

best = max((single_byte_xor(cipher, k) for k in range(256)), key=score_text)
print(best.decode())