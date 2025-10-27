#!/bin/bash
# 简单启动脚本 - 支持IP映射

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

# 启动应用
echo "🌐 启动Web应用..."
echo "💡 访问地址: http://10.161.76.22:8888"
conda activate ASB && python app.py
