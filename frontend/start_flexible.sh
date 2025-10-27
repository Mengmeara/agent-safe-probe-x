#!/bin/bash
# 灵活启动脚本 - 支持IP映射

# 获取本机IP地址
get_local_ip() {
    hostname -I | awk '{print $1}'
}

LOCAL_IP=$(get_local_ip)
MAPPED_IP="10.161.76.22"

echo "🚀 启动智能体安全检测工具..."
echo "🔍 网络配置:"
echo "  本机IP: $LOCAL_IP"
echo "  映射IP: $MAPPED_IP"
echo "  端口: 8888"
echo ""
echo "请选择启动方式:"
echo "1. localhost (127.0.0.1)"
echo "2. 所有接口 (0.0.0.0) - 推荐"
echo "3. 本机IP ($LOCAL_IP)"
echo "4. 自定义IP"

cd "$(dirname "$0")"

# 检查Python环境
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 未安装"
    exit 1
fi

# 检查依赖
echo "📦 检查依赖包..."
python3 -c "import flask, flask_cors, pandas, yaml" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  缺少依赖包，正在安装..."
    pip install flask flask-cors pandas pyyaml
fi

# 获取用户选择
read -p "请输入选择 (1-4): " choice

case $choice in
    1)
        echo "🌐 启动Web应用 (localhost)..."
        echo "💡 访问地址: http://localhost:8888"
        conda activate ASB && python app.py
        ;;
    2)
        echo "🌐 启动Web应用 (所有接口)..."
        echo "💡 访问地址: http://10.161.76.22:8888 (映射)"
        conda activate ASB && python app.py
        ;;
    3)
        echo "🌐 启动Web应用 (本机IP)..."
        echo "💡 访问地址: http://$LOCAL_IP:8888"
        conda activate ASB && python app.py
        ;;
    4)
        read -p "请输入IP地址: " custom_ip
        if [ -n "$custom_ip" ]; then
            echo "🌐 启动Web应用 ($custom_ip)..."
            echo "💡 访问地址: http://$custom_ip:8888"
            conda activate ASB && python app.py
        else
            echo "❌ IP地址不能为空"
            exit 1
        fi
        ;;
    *)
        echo "❌ 无效选择"
        exit 1
        ;;
esac
