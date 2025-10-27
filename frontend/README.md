# 智能体安全检测工具 Web应用

这是一个基于Web的智能体安全检测工具，提供友好的用户界面来检测和评估AI智能体的安全性和鲁棒性。

## 功能特性

- 🎯 **可视化配置**: 通过Web界面配置检测参数
- 🚀 **实时监控**: 实时查看检测进度和状态
- 📊 **结果分析**: 详细的检测结果统计和可视化
- 🔄 **任务管理**: 支持多个检测任务的管理
- 🐳 **容器化部署**: 支持Docker部署

## 快速开始

### 方法1: 直接运行

1. 确保已安装Python 3.9+
2. 安装依赖:
   ```bash
   pip install -r requirements.txt
   pip install -r web_app/requirements.txt
   ```

3. 配置IP地址 (可选):
   ```bash
   cd web_app
   python configure_ip.py
   ```

4. 启动应用:
   ```bash
   cd web_app
   python app.py
   ```

5. 访问 http://10.161.76.22:5000 (或您配置的IP地址)

### 方法2: 使用启动脚本

**快速启动 (使用指定IP 10.161.76.22):**
```bash
cd web_app
./start_ip.sh
```

**灵活启动 (可选择IP地址):**
```bash
cd web_app
./start_flexible.sh
```

**简单启动:**
```bash
cd web_app
./start.sh
```

### 方法3: Docker部署

```bash
cd web_app
docker-compose up -d
```

## IP地址配置

### 自动配置IP地址

运行IP配置脚本来自动检测和配置IP地址:

```bash
cd web_app
python configure_ip.py
```

脚本会提供以下选项:
- **localhost (127.0.0.1)**: 仅本机访问
- **所有接口 (0.0.0.0)**: 允许外部访问
- **本机IP**: 自动检测的本机IP地址
- **自定义IP**: 手动输入IP地址

### 手动配置

如果需要手动配置，可以编辑 `app.py` 文件中的以下行:

```python
app.run(host='10.161.76.22', port=5000, debug=True)
```

将 `10.161.76.22` 替换为您需要的IP地址。

## 使用说明

### 1. 配置检测参数

在Web界面中配置以下参数：

- **注入方法**: 选择观察提示注入或直接提示注入
- **攻击工具类型**: 选择all、agg、non-agg或test
- **LLM模型**: 指定要测试的模型，如ollama/llama3:8b
- **攻击类型**: 选择攻击类型，如clean_opi
- **任务数量**: 设置要执行的任务数量
- **防御类型**: 可选，指定防御机制
- **数据库选项**: 选择是否读写数据库

### 2. 启动检测

点击"开始检测"按钮启动检测任务。系统会：

1. 验证配置参数
2. 创建检测任务
3. 启动后台检测进程
4. 实时更新任务状态

### 3. 查看结果

检测完成后，可以查看：

- **统计信息**: 总测试数、成功攻击数、失败攻击数、攻击成功率
- **详细结果**: 每个测试的具体结果
- **任务历史**: 所有检测任务的历史记录

## API接口

### 配置相关

- `GET /api/config/template` - 获取配置模板
- `POST /api/config/validate` - 验证配置文件

### 检测相关

- `POST /api/detection/start` - 启动检测任务
- `GET /api/detection/status/<task_id>` - 获取任务状态
- `GET /api/detection/result/<task_id>` - 获取检测结果
- `POST /api/detection/cancel/<task_id>` - 取消检测任务

### 数据相关

- `GET /api/agents` - 获取可用智能体列表
- `GET /api/attack-tools` - 获取攻击工具列表
- `GET /api/tasks` - 获取所有任务列表

## 配置示例

```yaml
injection_method: observation_prompt_injection
attack_tool:
  - all
llms:
  - ollama/llama3:8b
attack_types:
  - clean_opi
task_num: 1
defense_type: null
write_db: false
read_db: false
```

## 项目结构

```
web_app/
├── app.py              # Flask后端应用
├── static/
│   └── index.html      # 前端页面
├── requirements.txt    # Web应用依赖
├── Dockerfile         # Docker配置
├── docker-compose.yml # Docker Compose配置
├── start.sh           # 启动脚本
└── README.md          # 说明文档
```

## 技术栈

- **后端**: Flask + Python
- **前端**: React + HTML/CSS/JavaScript
- **数据库**: 文件系统存储
- **容器化**: Docker + Docker Compose

## 注意事项

1. 确保系统已安装所需的LLM模型（如Ollama）
2. 检测过程可能需要较长时间，请耐心等待
3. 建议在测试环境中使用，避免影响生产系统
4. 定期清理日志文件以节省磁盘空间

## 故障排除

### 常见问题

1. **端口被占用**: 修改app.py中的端口号
2. **依赖安装失败**: 检查Python版本和网络连接
3. **检测任务失败**: 检查配置文件和模型可用性
4. **结果文件未找到**: 确认检测任务成功完成

### 日志查看

```bash
# 查看应用日志
tail -f logs/observation_prompt_injection/*/clean_opi-all_.log

# 查看Docker日志
docker-compose logs -f
```

## 贡献

欢迎提交Issue和Pull Request来改进这个工具。

## 许可证

本项目采用MIT许可证。
