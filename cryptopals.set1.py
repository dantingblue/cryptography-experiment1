import base64
import string
from itertools import cycle

def hex_to_base64(hex_string):
    """(1) 将十六进制字符串转换为Base64"""
    # 将十六进制转换为字节
    byte_data = bytes.fromhex(hex_string)
    # 将字节编码为Base64
    base64_data = base64.b64encode(byte_data)
    return base64_data.decode('ascii')

def fixed_xor(buffer1, buffer2):
    """(2) 固定长度的异或操作"""
    # 将十六进制字符串转换为字节
    bytes1 = bytes.fromhex(buffer1)
    bytes2 = bytes.fromhex(buffer2)
    
    # 检查长度是否相同
    if len(bytes1) != len(bytes2):
        raise ValueError("输入缓冲区长度必须相同")
    
    # 执行异或操作
    result = bytes([a ^ b for a, b in zip(bytes1, bytes2)])
    return result.hex()

def single_byte_xor_cipher(hex_string):
    """(3) 单字节异或密码破解"""
    ciphertext = bytes.fromhex(hex_string)
    best_score = float('-inf')
    best_key = None
    best_plaintext = None
    
    # 英文字母频率表
    freq = {
        ' ': 15, 'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
        's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8,
        'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
        'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
    }
    
    def score_text(text):
        """计算文本的英文可读性得分"""
        score = 0
        text_lower = text.lower()
        
        for char in text_lower:
            if char in freq:
                score += freq[char]
            elif not (32 <= ord(char) <= 126):  # 不可打印字符
                score -= 10
        
        return score
    
    # 尝试所有可能的单字节密钥（0-255）
    for key in range(256):
        try:
            # 解密
            plaintext = bytes([b ^ key for b in ciphertext])
            text = plaintext.decode('utf-8', errors='ignore')
            
            # 计算得分
            current_score = score_text(text)
            
            if current_score > best_score:
                best_score = current_score
                best_key = key
                best_plaintext = text
        except:
            continue
    
    return best_key, best_plaintext, best_score

def detect_single_char_xor(filename):
    """(4) 检测文件中的单字符异或加密文本"""
    best_overall_score = float('-inf')
    best_line = None
    best_key = None
    best_plaintext = None
    
    with open(filename, 'r') as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line:
                continue
            
            # 对每一行尝试单字节异或破解
            key, plaintext, score = single_byte_xor_cipher(line)
            
            if score > best_overall_score:
                best_overall_score = score
                best_line = line_num
                best_key = key
                best_plaintext = plaintext
    
    return best_line, best_key, best_plaintext, best_overall_score

def repeating_key_xor(plaintext, key):
    """(5) 实现重复密钥异或加密"""
    # 将输入转换为字节
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # 使用循环密钥进行异或
    result = bytes([p ^ k for p, k in zip(plaintext, cycle(key))])
    return result.hex()

def hamming_distance(b1, b2):
    """计算两个字节序列的汉明距离"""
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))

def break_repeating_key_xor(ciphertext):
    """(6) 破解重复密钥异或密码"""
    # 将十六进制转换为字节
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    
    def guess_key_length(data, max_key_length=40):
        """猜测密钥长度"""
        key_distances = []
        
        for key_len in range(2, min(max_key_length, len(data)//4)):
            # 取前4个密钥长度块计算平均汉明距离
            chunks = [data[i:i+key_len] for i in range(0, 4*key_len, key_len)]
            distances = []
            
            for i in range(len(chunks)):
                for j in range(i+1, len(chunks)):
                    if len(chunks[i]) == len(chunks[j]):
                        dist = hamming_distance(chunks[i], chunks[j]) / len(chunks[i])
                        distances.append(dist)
            
            if distances:
                avg_dist = sum(distances) / len(distances)
                key_distances.append((key_len, avg_dist))
        
        # 按距离排序，距离最小的最可能是正确密钥长度
        key_distances.sort(key=lambda x: x[1])
        return [k for k, _ in key_distances[:3]]
    
    def break_single_byte_xor_block(block):
        """破解单字节异或块"""
        best_score = float('-inf')
        best_key = 0
        
        freq = {' ': 15, 'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0}
        
        for key in range(256):
            try:
                plaintext = bytes([b ^ key for b in block])
                text = plaintext.decode('utf-8', errors='ignore')
                
                score = sum(freq.get(ch, 0) for ch in text.lower())
                if score > best_score:
                    best_score = score
                    best_key = key
            except:
                continue
        
        return best_key
    
    # 猜测密钥长度
    possible_lengths = guess_key_length(ciphertext)
    
    best_key = None
    best_plaintext = None
    best_score = float('-inf')
    
    for key_length in possible_lengths:
        # 将密文按密钥长度分组
        blocks = [[] for _ in range(key_length)]
        for i, byte in enumerate(ciphertext):
            blocks[i % key_length].append(byte)
        
        # 对每个分组破解单字节异或
        key_bytes = []
        for block in blocks:
            key_byte = break_single_byte_xor_block(bytes(block))
            key_bytes.append(key_byte)
        
        key = bytes(key_bytes)
        
        # 解密整个文本
        plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
        
        try:
            text = plaintext.decode('utf-8', errors='ignore')
            # 简单评分（计算字母和空格的比例）
            score = sum(1 for ch in text if ch.isalpha() or ch.isspace())
            
            if score > best_score:
                best_score = score
                best_key = key
                best_plaintext = text
        except:
            continue
    
    return best_key, best_plaintext

def main():
    """主函数 - 演示所有功能"""
    print("密码学挑战解决方案")
    print("=" * 50)
    
    # (1) Hex to Base64 示例
    print("\n1. Hex to Base64 转换:")
    hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64_output = hex_to_base64(hex_input)
    print(f"输入: {hex_input}")
    print(f"输出: {base64_output}")
    
    # (2) Fixed XOR 示例
    print("\n2. Fixed XOR 操作:")
    xor_input1 = "1c0111001f010100061a024b53535009181c"
    xor_input2 = "686974207468652062756c6c277320657965"
    xor_output = fixed_xor(xor_input1, xor_input2)
    print(f"输入1: {xor_input1}")
    print(f"输入2: {xor_input2}")
    print(f"输出: {xor_output}")
    
    # (3) Single-byte XOR cipher 示例
    print("\n3. 单字节异或密码破解:")
    xor_cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key, plaintext, score = single_byte_xor_cipher(xor_cipher)
    print(f"密文: {xor_cipher}")
    print(f"密钥: {key} (ASCII: '{chr(key) if 32 <= key <= 126 else '非打印字符'}')")
    print(f"明文: {plaintext}")
    
    # (4) Detect single-character XOR 示例
    print("\n4. 检测单字符异或加密:")
    # 这里需要有一个包含多行十六进制字符串的文件
    # 示例：创建一个测试文件
    test_lines = [
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f",
        "5f4d52415b5a4b52023d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d"
    ]
    
    with open('test_xor_lines.txt', 'w') as f:
        for line in test_lines:
            f.write(line + '\n')
    
    line_num, key, plaintext, score = detect_single_char_xor('test_xor_lines.txt')
    print(f"最可能是英文文本的行: {line_num}")
    print(f"使用的密钥: {key}")
    print(f"解密结果: {plaintext}")
    
    # (5) Repeating-key XOR 示例
    print("\n5. 重复密钥异或加密:")
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    encrypted = repeating_key_xor(plaintext, key)
    print(f"明文: {plaintext}")
    print(f"密钥: {key}")
    print(f"密文: {encrypted}")
    
    # (6) Break repeating-key XOR 示例
    print("\n6. 破解重复密钥异或密码:")
    # 使用上面加密的结果进行解密测试
    key_found, decrypted_text = break_repeating_key_xor(encrypted)
    print(f"找到的密钥: {key_found.decode('utf-8', errors='replace')}")
    print(f"解密文本: {decrypted_text}")

if __name__ == "__main__":
    main()