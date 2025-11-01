from app.server import socketio, app, get_local_ip

if __name__ == '__main__':
    local_ip = get_local_ip()
    print("🚀 启动Web应用...")
    print("绑定地址: 0.0.0.0:8888 (所有网络接口)")
    print(f"本机访问: http://localhost:8888")
    print(f"本机IP访问: http://{local_ip}:8888")
    print("映射访问: http://10.161.76.22:8888")
    print()
    print("启动智能体安全检测工具API服务器...")
    print("💡 提示: 学校内网访问地址")
    print(f"💡 注意: 本机IP是 {local_ip}，但通过 10.161.76.22 映射访问")
    socketio.run(app, host='0.0.0.0', port=8888, debug=True, allow_unsafe_werkzeug=True)
