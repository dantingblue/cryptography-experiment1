def xor_buffers(buf1, buf2):
    return bytes(a ^ b for a, b in zip(buf1, buf2))

hex1 = input("输入第一个十六进制: ")
hex2 = input("输入第二个十六进制: ")

result = xor_buffers(bytes.fromhex(hex1), bytes.fromhex(hex2))
print("异或结果:", result.hex())