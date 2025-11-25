import string
import re
from operator import itemgetter, attrgetter

latter_frequency = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .15000
}

def English_Scoring(t):
    return sum([latter_frequency.get(chr(i),0) for i in t.lower()])     

def Single_XOR(s,single_character):
    t = b''
    for i in s:
        t = t+bytes([i^single_character])
    return t

def ciphertext_XOR(s,single_character):
    s = bytes.fromhex(s)
    ciphertext = Single_XOR(s,single_character)
    score = English_Scoring(ciphertext)
    return {
        'Single character': single_character,
        'ciphertext': ciphertext,
        'score': score
    }

if __name__ == '__main__':
    _data = []
    try:
        with open(r'C:\Users\惠丹婷\.vscode\密码实验\实验一\3-4\3-4-1.txt', 'r') as f:
            s = f.read().splitlines()
        
        print(f"读取到 {len(s)} 行数据")
        
        for line_num, i in enumerate(s):
            if i.strip():  # 跳过空行
                print(f"处理第 {line_num+1} 行: {i[:20]}...")
                for j in range(256):
                    data = ciphertext_XOR(i,j)
                    _data.append(data)
        
        if _data:
            best_score = sorted(_data, key=lambda x: x['score'], reverse=True)[0]
            print("最佳结果:")
            for i in best_score:
                print("{}: {}".format(i.title(), best_score[i]))
        else:
            print("没有处理任何数据")
            
    except FileNotFoundError:
        print("文件未找到，请检查路径")
    except Exception as e:
        print(f"发生错误: {e}")