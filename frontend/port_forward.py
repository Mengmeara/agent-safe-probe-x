#!/usr/bin/env python3
"""
端口转发脚本
将10.161.76.22:8888的请求转发到localhost:8888
"""

import socket
import threading
import sys

def forward_connection(client_socket, target_host, target_port):
    """转发连接"""
    try:
        # 连接到目标服务器
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_host, target_port))
        
        # 创建两个线程来转发数据
        def forward_data(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.send(data)
            except:
                pass
            finally:
                source.close()
                destination.close()
        
        # 启动转发线程
        thread1 = threading.Thread(target=forward_data, args=(client_socket, target_socket))
        thread2 = threading.Thread(target=forward_data, args=(target_socket, client_socket))
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        # 等待线程结束
        thread1.join()
        thread2.join()
        
    except Exception as e:
        print(f"转发连接时出错: {e}")
        client_socket.close()

def start_port_forward(local_ip, local_port, target_host, target_port):
    """启动端口转发"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((local_ip, local_port))
        server_socket.listen(5)
        print(f"端口转发启动: {local_ip}:{local_port} -> {target_host}:{target_port}")
        
        while True:
            client_socket, addr = server_socket.accept()
            print(f"新连接来自: {addr}")
            
            # 为每个连接创建新线程
            thread = threading.Thread(
                target=forward_connection,
                args=(client_socket, target_host, target_port)
            )
            thread.daemon = True
            thread.start()
            
    except Exception as e:
        print(f"启动端口转发失败: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    # 配置
    LOCAL_IP = "10.161.76.22"  # 要监听的IP
    LOCAL_PORT = 8888          # 要监听的端口
    TARGET_HOST = "127.0.0.1" # 目标主机
    TARGET_PORT = 8888         # 目标端口
    
    print("🚀 启动端口转发服务...")
    print(f"监听: {LOCAL_IP}:{LOCAL_PORT}")
    print(f"转发到: {TARGET_HOST}:{TARGET_PORT}")
    
    try:
        start_port_forward(LOCAL_IP, LOCAL_PORT, TARGET_HOST, TARGET_PORT)
    except KeyboardInterrupt:
        print("\n停止端口转发服务")
        sys.exit(0)
