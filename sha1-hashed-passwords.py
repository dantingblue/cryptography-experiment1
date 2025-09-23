import hashlib
import itertools


# 目标SHA1哈希值
target_hash = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

# 原始字符组，每组有2个候选字符
char_groups = [
    ['Q', 'q'],
    ['W', 'w'],
    ['%', '5'],
    ['8', '('],
    ['=', '0'],
    ['I', 'i'],
    ['*', '+'],
    ['n', 'N']
]

# 使用 itertools.product 生成所有组合，每组选择1个字符，共 2^8 = 256 种组合
for combo in itertools.product(*char_groups):
    # combo 是长度8的元组，例如 ('Q','W','%','8','=','I','*','n')
    base_string = "".join(combo)

    # 对 base_string 生成所有全排列
    for perm in itertools.permutations(base_string, 8):
        candidate = "".join(perm)  # 将元组转换成字符串
        candidate_hash = hashlib.sha1(candidate.encode("utf-8")).hexdigest()

        # 比较哈希值
        if candidate_hash == target_hash:
            print(f"找到匹配字符串: {candidate}")
            exit(0)  # 找到后立即退出整个程序


