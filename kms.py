from py_ecc.bn128 import G1, multiply, add, pairing
from hashlib import sha256
import random
from typing import List, Tuple

# 定义全局参数
PRIME = 97  # 大素数
THRESHOLD_T = 2  # 低阈值
THRESHOLD_N = 4  # 高阈值 (需满足 t < n')
g1_gen = G1

class Node:
    def __init__(self, node_id, is_meta=False):
        self.id = node_id
        self.x = random.randint(1, PRIME - 1)  # 公开信息
        self.shares = {}  # 存储子份额
        self.is_meta = is_meta
        self.poly = None  # 元节点的多项式
        self.group_key = None  # 组密钥
        self.session_key = None  # 系统会话密钥

    def generate_bivariate_poly(self, t, n_prime):
        """生成非对称双变量多项式（t阶x，n'阶y）"""
        if self.is_meta:
            self.poly = [
                [random.randint(1, PRIME - 1) for _ in range(n_prime + 1)]
                for _ in range(t + 1)
            ]
        else:
            self.poly = None  # 非元节点不需要生成多项式

    def compute_share(self, other_node):
        """计算给其他节点的子份额 f_i(x_j, y) 和 f_i(x, x_j)"""
        if self.poly is None:
            raise ValueError(f"Node {self.id} 的多项式未初始化，无法计算子份额。")

        x_j = other_node.x
        share_xjy = sum(
            self.poly[i][j] * (x_j ** i) % PRIME
            for i in range(THRESHOLD_T + 1)
            for j in range(THRESHOLD_N + 1)
        ) % PRIME

        share_xxj = sum(
            self.poly[i][j] * (x_j ** j) % PRIME
            for i in range(THRESHOLD_T + 1)
            for j in range(THRESHOLD_N + 1)
        ) % PRIME

        return share_xjy, share_xxj

def mod_inverse(a, m):
    """计算a模m的逆元"""
    def extended_gcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} 在模 {m} 下没有逆元")
    return x % m

def lagrange_interpolation(points, prime):
    """通过拉格朗日插值法恢复秘密"""
    secret = 0
    for i in range(len(points)):
        xi, yi = points[i]
        term = yi
        for j in range(len(points)):
            if i != j:
                xj = points[j][0]
                try:
                    term = term * mod_inverse((xi - xj) % prime, prime) * (-xj) % prime
                except ValueError as e:
                    raise ValueError(f"拉格朗日插值时出错: {e}")
        secret = (secret + term) % prime
    return secret

class Network:
    def __init__(self):
        self.nodes = []  # 存储所有节点
        self.shared_state = {}  # 共享状态

    def add_node(self, node):
        self.nodes.append(node)

    def remove_node(self, node_id):
        self.nodes = [node for node in self.nodes if node.id != node_id]

    def broadcast(self, sender, data_type, data):
        data_str = str(data)
        print(f"[Node {sender.id}] 广播 {data_type}: {data_str[:20]}...")
        self.shared_state[sender.id] = {data_type: data}

    def get_shared_state(self, node_id, data_type):
        return self.shared_state.get(node_id, {}).get(data_type)

def key_generation(network, nodes):
    """
    根据论文4.2.1的描述进行密钥生成
    """
    meta_nodes = [n for n in nodes if n.is_meta]
    if len(meta_nodes) < THRESHOLD_T + 1:
        raise ValueError(f"元节点数量不足，需要至少 {THRESHOLD_T + 1} 个元节点")

    for node in meta_nodes:
        node.generate_bivariate_poly(THRESHOLD_T, THRESHOLD_N)
        print(f"Node {node.id} poly initialized: {node.poly}")

    for meta_node in meta_nodes:
        for receiver in nodes:
            if receiver.id != meta_node.id:
                share_xjy, share_xxj = meta_node.compute_share(receiver)
                receiver.shares[meta_node.id] = (share_xjy, share_xxj)

    for node in nodes:
        sum_xjy = sum(node.shares[meta_id][0] for meta_id in node.shares) % PRIME
        sum_xxj = sum(node.shares[meta_id][1] for meta_id in node.shares) % PRIME
        node.shares["low_order"] = (sum_xjy, sum_xxj)

    for meta_node in meta_nodes:
        for receiver in nodes:
            if receiver.id != meta_node.id:
                share_xjy, share_xxj = meta_node.compute_share(receiver)
                receiver.shares[meta_node.id] = (share_xjy, share_xxj)

    for node in nodes:
        sum_xjy = sum(node.shares[meta_id][0] for meta_id in node.shares if meta_id != "low_order") % PRIME
        sum_xxj = sum(node.shares[meta_id][1] for meta_id in node.shares if meta_id != "low_order") % PRIME
        node.shares["high_order"] = (sum_xjy, sum_xxj)

    print("密钥生成完成，所有节点获得低阶和高阶份额")

# --------------------- 4.2.2 组密钥分发 ---------------------
# 伪随机函数实现，基于 SHA-256
def prf(seed: str, input_value: str) -> int:
    """
    伪随机函数，基于SHA-256哈希函数实现
    :param seed: 种子字符串
    :param input_value: 输入值
    :return: 生成的伪随机整数
    """
    # 将种子和输入值拼接后进行哈希
    hash_input = f"{seed}_{input_value}".encode()
    hash_output = sha256(hash_input).hexdigest()
    # 将哈希输出转换为整数，并取模PRIME
    return int(hash_output, 16) % PRIME

def group_key_distribution(network, initiator, members):
    """
    使用伪随机函数进行组密钥分发
    :param network: 网络对象
    :param initiator: 发起组密钥分发的节点
    :param members: 组内成员节点列表
    """
    # 生成随机数γ
    gamma = random.randint(1, PRIME - 1)

    # 使用PRF生成共享密钥点
    points = []
    for member in members:
        k_ij = initiator.shares[member.id][0]  # 共享密钥
        # 使用PRF生成伪随机数，作为X, Y坐标
        x_value = prf(f"{initiator.id}_{member.id}", str(k_ij))
        y_value = prf(f"{initiator.id}_{member.id}", str(k_ij + 1))
        X = x_value * gamma % PRIME
        Y = y_value * gamma % PRIME
        points.append((X, Y))

    # 生成组密钥
    GK = random.randint(1, PRIME - 1)
    poly_coeffs = [GK] + [random.randint(1, PRIME - 1) for _ in range(len(members) - 1)]

    # 生成多项式点
    polynomial_points = [(i, sum(coeff * (i ** j) % PRIME for j, coeff in enumerate(poly_coeffs)) % PRIME) for i in range(len(members))]

    # 生成组密钥摘要并广播
    summary = sha256(str(GK).encode()).hexdigest()
    network.broadcast(initiator, "组密钥摘要", summary)

    # 广播多项式点
    network.broadcast(initiator, "多项式点", polynomial_points)

    # 设置组密钥和多项式点
    initiator.group_key = GK
    initiator.polynomial_points = polynomial_points
    for member in members:
        member.group_key = GK
        member.polynomial_points = polynomial_points

def verify_group_key(points, summary, group_key):
    """
    验证组密钥
    :param points: 多项式点
    :param summary: 组密钥摘要
    :param group_key: 组密钥
    """
    try:
        interpolated_key = lagrange_interpolation(points, PRIME)
    except ValueError as e:
        raise ValueError(f"组密钥验证失败: {e}")

    if interpolated_key != group_key:
        raise ValueError("组密钥验证失败")

    if summary != sha256(str(group_key).encode()).hexdigest():
        raise ValueError("摘要验证失败")

    print("组密钥验证成功")

# --------------------- 4.2.3 节点出入 ---------------------
def node_join(new_node, helpers, network, t, n_prime):
    """
    新节点加入
    :param new_node: 新加入的节点
    :param helpers: 帮助新节点加入的现有节点列表
    :param network: 网络对象
    :param t: x的阶数
    :param n_prime: y的阶数
    """
    new_node.generate_bivariate_poly(t, n_prime)
    shares = []
    for helper in helpers:
        share_xjy, share_xxj = helper.compute_share(new_node)
        shares.append((helper.x, share_xjy))

    try:
        recovered_share = lagrange_interpolation(shares[:t + 1], PRIME)
    except ValueError as e:
        raise ValueError(f"新节点恢复份额失败: {e}")
    new_node.shares[helper.id] = (recovered_share, 0)
    join_group_if_desired(new_node, helpers, network)

def join_group_if_desired(new_node, helpers, network):
    """
    如果新节点选择加入组，则执行加入操作
    :param new_node: 新加入的节点
    :param helpers: 帮助新节点加入的现有节点列表
    :param network: 网络对象
    """
    join_group = input(f"Node {new_node.id}, would you like to join the group? (yes/no): ").strip().lower()
    if join_group == "yes":
        # 假设组密钥和多项式点已经由helpers提供
        group_key = helpers[0].group_key  # 示例，实际应从helpers中获取
        polynomial_points = helpers[0].polynomial_points  # 示例

        # 验证组密钥
        try:
            verify_group_key(polynomial_points, sha256(str(group_key).encode()).hexdigest(), group_key)
            print(f"Node {new_node.id} 加入组成功")
            # 更新新节点的组密钥和多项式点信息
            new_node.group_key = group_key
            new_node.polynomial_points = polynomial_points
        except ValueError as e:
            print(str(e))
    else:
        print(f"Node {new_node.id} 选择不加入组")

def node_exit(exit_node, nodes, network, exit_group=False):
    """
    节点退出组或整个系统
    :param exit_node: 退出的节点
    :param nodes: 当前节点列表
    :param network: 网络对象
    :param exit_group: 是否仅退出组（True）还是退出整个系统（False）
    """
    print(f"Node {exit_node.id} 开始退出流程...")
    if exit_group:
        # 节点退出组，但保留在系统中
        print(f"Node {exit_node.id} 退出组，但保留在系统中")
        exit_node.group_key = None  # 清除组密钥

        # 获取当前组内成员
        group_members = [node for node in nodes if node.group_key is not None]
        if group_members:
            # 更新组密钥
            group_key_update(network, group_members[0], group_members)
        else:
            print("组内无其他成员，无需更新组密钥")
    else:
        # 节点完全退出系统
        print(f"Node {exit_node.id} 完全退出系统")
        nodes.remove(exit_node)
        network.remove_node(exit_node.id)
        exit_node.shares.clear()
        exit_node.group_key = None
        exit_node.session_key = None

        # 更新系统会话密钥
        if nodes:
            print("更新系统会话密钥...")
            for node in nodes:
                node.session_key = random.randint(1, PRIME - 1)
        else:
            print("系统中无其他节点，无需更新会话密钥")

    print(f"Node {exit_node.id} 退出完成")

def manage_nodes(network, nodes, new_node=None, exit_node=None, exit_group=False):
    """
    动态管理节点加入或退出
    """
    if new_node:
        try:
            node_join(new_node, nodes[:2], network, THRESHOLD_T, THRESHOLD_N)
            nodes.append(new_node)
            network.add_node(new_node)
            print(f"新节点 {new_node.id} 已加入系统")
        except ValueError as e:
            print(f"新节点加入失败: {e}")

    if exit_node:
        try:
            node_exit(exit_node, nodes, network, exit_group)
            print(f"节点 {exit_node.id} 已退出")
        except ValueError as e:
            print(f"节点退出失败: {e}")

    return nodes

# --------------------- 4.2.4 组密钥更新 ---------------------
def group_key_update(network, initiator, members):
    """
    使用伪随机函数进行组密钥更新
    :param network: 网络对象
    :param initiator: 发起更新的节点
    :param members: 当前组内的成员节点列表
    """
    # 生成新的随机数𝛾′
    gamma_prime = random.randint(1, PRIME - 1)

    # 为每个成员生成新的共享密钥点
    new_shared_secrets = []
    for member in members:
        # 使用伪随机函数生成新的共享密钥点
        seed = f"{initiator.id}_{member.id}"
        W_i_prime = prf(seed, f"{gamma_prime}")
        W_i_plus_1_prime = prf(seed, f"{gamma_prime + 1}")
        new_shared_secrets.append((W_i_prime, W_i_plus_1_prime))

    # 生成新的组密钥
    new_group_key = random.randint(1, PRIME - 1)

    # 构建新的多项式点
    new_points = [(0, new_group_key)]
    for i, (W_i_prime, _) in enumerate(new_shared_secrets):
        new_points.append((i + 1, W_i_prime))

    # 生成新的组密钥摘要
    new_summary = sha256(str(new_group_key).encode()).hexdigest()

    # 广播新的组密钥摘要和多项式点
    network.broadcast(initiator, "新组密钥摘要", new_summary)
    network.broadcast(initiator, "新的多项式点", new_points)

    # 组内成员验证新的组密钥
    for member in members:
        # 模拟成员收到广播信息
        received_points = new_points
        received_summary = new_summary

        # 验证组密钥
        verify_group_key(received_points, received_summary, new_group_key)

if __name__ == "__main__":
    network = Network()
    nodes = [Node(i, is_meta=(i < 3)) for i in range(5)]

    for node in nodes:
        network.add_node(node)

    key_generation(network, nodes)
# 阶段2: 组密钥分发（节点0发起）
    group_key_distribution(network, nodes[0], nodes[1:3])

    while True:
        action = input("请输入操作类型（join/exit/continue）：").strip().lower()
        if action == "join":
            new_node_id = int(input("请输入新节点的ID："))
            new_node = Node(new_node_id, is_meta=True)
            nodes = manage_nodes(network, nodes, new_node=new_node)
        elif action == "exit":
            exit_node_id = int(input("请输入退出节点的ID："))
            exit_node = next((node for node in nodes if node.id == exit_node_id), None)
            if exit_node:
                exit_group = input("仅退出组（输入 'group'）还是退出整个系统（输入 'system'）？").strip().lower()
                exit_group = (exit_group == "group")
                nodes = manage_nodes(network, nodes, exit_node=exit_node, exit_group=exit_group)
            else:
                print(f"节点 {exit_node_id} 不存在，无法退出。")
        elif action == "continue":
            break
        else:
            print("无效的操作类型，请输入 'join'、'exit' 或 'continue'。")

    print("程序结束")
