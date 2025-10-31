#!/usr/bin/env python3
"""
IP地址配置脚本
自动检测和配置Web应用的IP地址
"""

import socket
import os
import sys

def get_local_ip():
    """获取本机IP地址"""
    try:
        # 连接到一个外部地址来获取本机IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_all_ips():
    """获取所有可用的IP地址"""
    ips = []
    try:
        import netifaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    if ip != '127.0.0.1' and not ip.startswith('169.254'):
                        ips.append(ip)
    except ImportError:
        # 如果没有netifaces，使用简单方法
        local_ip = get_local_ip()
        if local_ip != "127.0.0.1":
            ips.append(local_ip)
    
    return ips

def configure_app_ip():
    """配置应用IP地址"""
    print("🌐 智能体安全检测工具 - IP地址配置")
    print("=" * 50)
    
    local_ip = get_local_ip()
    all_ips = get_all_ips()
    
    print(f"检测到的本机IP: {local_ip}")
    if all_ips:
        print(f"所有可用IP: {', '.join(all_ips)}")
    print()
    
    print("请选择配置方式:")
    print("1. localhost (127.0.0.1) - 仅本机访问")
    print("2. 所有接口 (0.0.0.0) - 允许外部访问")
    print("3. 本机IP - 使用检测到的本机IP")
    if all_ips:
        for i, ip in enumerate(all_ips, 4):
            print(f"{i}. {ip}")
    print("5. 自定义IP - 手动输入IP地址")
    print("0. 退出")
    
    while True:
        try:
            choice = input("\n请输入选择 (0-5): ").strip()
            
            if choice == "0":
                print("退出配置")
                return None, None
            
            elif choice == "1":
                return "127.0.0.1", 5000
            
            elif choice == "2":
                return "0.0.0.0", 5000
            
            elif choice == "3":
                return local_ip, 5000
            
            elif choice == "5":
                custom_ip = input("请输入自定义IP地址: ").strip()
                if custom_ip:
                    return custom_ip, 5000
                else:
                    print("IP地址不能为空")
                    continue
            
            elif choice.isdigit() and 4 <= int(choice) <= 3 + len(all_ips):
                idx = int(choice) - 4
                return all_ips[idx], 5000
            
            else:
                print("无效选择，请重新输入")
                
        except KeyboardInterrupt:
            print("\n退出配置")
            return None, None
        except Exception as e:
            print(f"输入错误: {e}")

def update_app_file(host, port):
    """更新app.py文件中的配置"""
    app_file = os.path.join(os.path.dirname(__file__), 'app.py')
    
    if not os.path.exists(app_file):
        print("❌ 找不到app.py文件")
        return False
    
    try:
        with open(app_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 查找并替换配置
        lines = content.split('\n')
        new_lines = []
        
        for line in lines:
            if 'app.run(' in line and 'host=' in line:
                new_line = f"    app.run(host='{host}', port={port}, debug=True)"
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        
        new_content = '\n'.join(new_lines)
        
        with open(app_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"✅ 已更新app.py配置: {host}:{port}")
        return True
        
    except Exception as e:
        print(f"❌ 更新配置文件失败: {e}")
        return False

def main():
    """主函数"""
    host, port = configure_app_ip()
    
    if host and port:
        if update_app_file(host, port):
            print("\n🎉 配置完成!")
            print(f"Web应用将运行在: http://{host}:{port}")
            print("\n启动命令:")
            print("cd web_app")
            print("python app.py")
        else:
            print("\n❌ 配置失败")
    else:
        print("\n配置已取消")

if __name__ == '__main__':
    main()
