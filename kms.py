import json
import random
import time
from sympy import symbols, expand, interpolate
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib
import socket
import ssl
import threading
import time
import logging

# 配置日志模块
logging.basicConfig(
    level=logging.INFO,  # 设置日志级别为 INFO
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s',  # 日志格式
    datefmt='%Y-%m-%d %H:%M:%S'  # 时间格式
)

def create_ssl_context(node_info, trusted_certs, is_server=False):
    if is_server:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile=node_info["cert"], keyfile=node_info["key"])
    for cert_path in trusted_certs:
        context.load_verify_locations(cert_path)
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def start_server(node_info, context):
    host = node_info["host"]
    port = node_info["port"]
    node_id = node_info["node_id"]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with context.wrap_socket(sock, server_side=True) as ssock:
            ssock.bind((host, port))
            ssock.listen(5)
            logging.info(f"节点 {node_id} 作为服务端启动，监听 {host}:{port}")
            time.sleep(2)  # 确保服务端完全启动

            while True:
                try:
                    conn, addr = ssock.accept()
                    with conn:
                        logging.info(f"节点 {node_id} 收到来自 {addr} 的连接")
                        data = conn.recv(1024)
                        logging.info(f"节点 {node_id} 收到响应: {data}")
                        conn.sendall(b"Hello from server")
                except Exception as e:
                    logging.error(f"节点 {node_id} 服务端错误: {e}")

def start_client(node_info, target_node_info, context):
    host = target_node_info["host"]
    port = target_node_info["port"]
    node_id = node_info["node_id"]
    target_id = target_node_info["node_id"]
    retry_count = 0
    max_retries = 5

    while retry_count < max_retries:
        try:
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=f"node{target_id}") as ssock:
                    ssock.sendall(f"Hello from node {node_id}".encode())
                    data = ssock.recv(1024)
                    logging.info(f"节点 {node_id} 向节点 {target_id} 发送消息，收到响应: {data}")
                    break
        except ConnectionRefusedError:
            retry_count += 1
            logging.warning(f"节点 {node_id} 连接到节点 {target_id} 被拒绝，重试中 ({retry_count}/{max_retries})")
            time.sleep(1)
        except Exception as e:
            logging.error(f"节点 {node_id} 客户端连接失败: {e}")
            break

def get_file_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except FileNotFoundError:
        return None

# 定义符号变量
x, y = symbols('x y')

# 读取配置文件
def load_config(config_path="config.json"):
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
            print("配置文件内容:", content)  # 调试信息
            if not content:
                print(f"错误: 配置文件 {config_path} 为空")
                return None
            try:
                config = json.loads(content)
                return config
            except json.JSONDecodeError as e:
                print(f"错误: 配置文件 {config_path} 格式不正确，具体错误: {e}")
                return None
    except FileNotFoundError:
        print(f"错误: 配置文件 {config_path} 未找到")
        return None
    except Exception as e:
        print(f"错误: 读取配置文件 {config_path} 时发生未知错误: {e}")
        return None

# 生成非对称二元多项式（高阶份额）
def generate_high_order_shares(master_nodes, degree_x, degree_y, prime):
    master_shares = {}
    for node in master_nodes:
        coefficients = [[random.randint(1, prime-1) for _ in range(degree_y + 1)] for _ in range(degree_x + 1)]
        poly = sum(coefficients[m][n] * x**m * y**n for m in range(degree_x + 1) for n in range(degree_y + 1))
        master_shares[node] = (expand(poly), coefficients)
    return master_shares

# 计算子份额（用于第一次分发）
def generate_low_order_shares(master_shares, nodes, prime):
    low_shares = {node: [] for node in nodes}
    for node in nodes:
        for master_id, (poly, _) in master_shares.items():
            low_shares[node].append(poly.subs({x: node, y: master_id}) % prime)
    return low_shares

# 计算高阶份额（用于第二次分发）
def generate_complete_shares(low_shares, nodes, prime):
    complete_shares = {}
    for node in nodes:
        points = list(low_shares.keys())
        values = [low_shares[p][min(node - 1, len(low_shares[p]) - 1)] for p in points]
        complete_shares[node] = interpolate(list(zip(points, values)), x) % prime
    return complete_shares

# 计算共享密钥
def compute_shared_keys(complete_shares, prime):
    shared_keys = {}
    for i, poly_i in complete_shares.items():
        for j, poly_j in complete_shares.items():
            if i != j:
                key_ij = (poly_i.subs(x, j) + poly_j.subs(x, i)) % prime
                shared_keys[(i, j)] = key_ij
    return shared_keys

# 组密钥协商
def group_key_agreement(group_members, initiator, shared_keys, prime):
    random_secret = random.randint(1, prime-1)
    points = []
    for member in group_members:
        for other in group_members:
            if member != other:
                try:
                    key = shared_keys[(min(member, other), max(member, other))]
                    x_value = member * (max(group_members) + 1) + other  # 生成唯一的 x 值
                    y_value = (random_secret * key) % prime
                    points.append((x_value, y_value))
                except KeyError:
                    print(f"警告: 成员 {member} 和 {other} 的共享密钥不存在，跳过该节点对")
                    continue
    
    print("插值点:", points)  # 调试信息
    if len(points) < 2:
        raise ValueError("插值点数量不足，无法生成多项式")
    
    try:
        group_key_poly = interpolate(points, x) % prime
    except Exception as e:
        print("插值失败:", e)
        group_key_poly = None
    
    group_key = random.randint(1, prime-1)
    group_key_points = [(i, (group_key * i) % prime) for i in group_members]
    
    group_key_broadcast = {
        "poly": group_key_poly,
        "points": group_key_points,
        "initiator": initiator
    }
    return group_key_broadcast

def update_session_keys(nodes_info, old_nodes, prime, config):
    global shared_keys  # 使用全局变量存储共享密钥

    nodes = [node["node_id"] for node in nodes_info]
    new_nodes = list(set(nodes) - set(old_nodes))  # 仅获取新加入的节点
    master_nodes = [node["node_id"] for node in nodes_info if node["is_master"]]

    # 没有新节点加入，不需要更新
    if not new_nodes:
        return shared_keys

    print(f"检测到新节点 {new_nodes} 加入，更新会话密钥...")

    # 只为新节点生成高阶份额
    new_master_shares = generate_high_order_shares(new_nodes, config["degree_x"], config["degree_y"], prime)

    # 只计算新节点的低阶份额
    new_low_shares = generate_low_order_shares(new_master_shares, nodes, prime)

    # 只计算新节点的完整份额
    new_complete_shares = generate_complete_shares(new_low_shares, nodes, prime)

    # 计算 **新节点与原有节点** 之间的共享密钥，不更新原有节点的密钥
    for new_node in new_nodes:
        for old_node in old_nodes:
            key = (new_complete_shares[new_node].subs(x, old_node) +
                   new_complete_shares[old_node].subs(x, new_node)) % prime
            shared_keys[(new_node, old_node)] = key
            shared_keys[(old_node, new_node)] = key  # 共享密钥是对称的

    print("更新后的会话密钥:", shared_keys)
    return shared_keys

# 更新组密钥
def update_group_keys(groups_info, shared_keys, prime):
    group_key_results = {}
    for group in groups_info:
        group_id = group["group_id"]
        group_members = group["members"]
        initiator = group["initiator"]
        group_key_info = group_key_agreement(group_members, initiator, shared_keys, prime)
        group_key_results[group_id] = group_key_info
    return group_key_results

# 处理配置文件修改
class ConfigFileHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        self.last_modified = 0

    def on_modified(self, event):
        if event.src_path.endswith("config.json"):
            current_time = time.time()
            if current_time - self.last_modified > 2:  # 2秒内不重复触发
                print("\n检测到 config.json 文件被修改，重新加载配置...")
                time.sleep(1)  # 等待1秒，确保文件写入完成
                self.callback()
                self.last_modified = current_time

def main(is_initial_run=False):
    global config, shared_keys, group_key_results, old_config

    # 加载配置
    config = load_config()
    if config is None:
        return

    prime = config["prime"]
    nodes_info = config["nodes"]
    groups_info = config["groups"]

    # 提取节点信息
    nodes = [node["node_id"] for node in nodes_info]
    master_nodes = [node["node_id"] for node in nodes_info if node["is_master"]]
    
    # 收集所有节点的证书路径
    all_cert_paths = [node["cert"] for node in nodes_info]

    # 为每个节点启动服务端
    for node_info in nodes_info:
        trusted_certs = [cert for cert in all_cert_paths if cert != node_info["cert"]]
        context = create_ssl_context(node_info, trusted_certs, is_server=True)
        threading.Thread(target=start_server, args=(node_info, context), name=f"Node{node_info['node_id']}-Server", daemon=True).start()

    # 为每个节点启动客户端
    for node_info in nodes_info:
        for target_node_info in nodes_info:
            if node_info["node_id"] != target_node_info["node_id"]:  # 不连接自己
                trusted_certs = [cert for cert in all_cert_paths if cert != node_info["cert"]]
                context = create_ssl_context(node_info, trusted_certs, is_server=False)
                threading.Thread(target=start_client, args=(node_info, target_node_info, context), name=f"Node{node_info['node_id']}-Client", daemon=True).start()
    
    if is_initial_run:
        print("初始运行，生成密钥...")

        # 生成高阶份额
        master_shares = generate_high_order_shares(master_nodes, config["degree_x"], config["degree_y"], prime)

        # 生成低阶份额
        low_shares = generate_low_order_shares(master_shares, nodes, prime)

        # 生成完整份额
        complete_shares = generate_complete_shares(low_shares, nodes, prime)

        # 计算初始所有节点之间的共享密钥
        shared_keys = compute_shared_keys(complete_shares, prime)

        # 计算初始组密钥
        group_key_results = update_group_keys(groups_info, shared_keys, prime)

    else:
        # 处理节点和组的增删
        if "old_config" not in globals():
            old_config = {"nodes": [], "groups": []}
        old_nodes = old_config["nodes"]
        old_groups = old_config["groups"]

        # 检测新增和移除的节点
        new_nodes = list(set(nodes) - set(old_nodes))
        removed_nodes = list(set(old_nodes) - set(nodes))

        # 检测组的变化
        update_group_keys_flag = False
        new_groups = [group for group in groups_info if group not in old_groups]
        removed_groups = [group for group in old_groups if group not in groups_info]

        for group in groups_info:
            old_group = next((g for g in old_groups if g["group_id"] == group["group_id"]), None)
            if old_group:
                old_members = set(old_group["members"])
                current_members = set(group["members"])
                if old_members != current_members:
                    update_group_keys_flag = True
            else:
                update_group_keys_flag = True

        if new_groups or removed_groups:
            update_group_keys_flag = True

        # **只更新新增节点的会话密钥**
        if new_nodes:
            print(f"检测到新节点 {new_nodes} 加入，更新会话密钥...")
            shared_keys = update_session_keys(nodes_info, old_nodes, prime, config)

        # 移除退出节点的密钥
        if removed_nodes:
            print(f"检测到节点 {removed_nodes} 退出，移除相关会话密钥...")
            shared_keys = {k: v for k, v in shared_keys.items() if k[0] not in removed_nodes and k[1] not in removed_nodes}

        # 只在必要时更新组密钥
        if update_group_keys_flag:
            print("检测到组变化，更新组密钥...")
            group_key_results = update_group_keys(groups_info, shared_keys, prime)

    # 更新旧配置
    old_config = {"nodes": nodes, "groups": groups_info}

    # 打印结果
    print("当前会话密钥:", shared_keys)
    print("当前组密钥:", group_key_results)

# 启动文件监控
if __name__ == "__main__":
    # 首次运行，标记为初始运行
    main(is_initial_run=True)

    # 创建文件监控
    event_handler = ConfigFileHandler(lambda: main(is_initial_run=False))
    observer = Observer()
    observer.schedule(event_handler, path=".", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
