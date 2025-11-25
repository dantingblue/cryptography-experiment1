import base64

hex_str = input("请输入十六进制字符串: ")
hex_str = hex_str.replace(" ", "")  # 移除空格
bytes_data = bytes.fromhex(hex_str)
base64_str = base64.b64encode(bytes_data).decode()
print("Base64结果:", base64_str)
