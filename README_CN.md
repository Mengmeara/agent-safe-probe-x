# Agent Safe Probe (ASP-X)

**ASP-X (Agent Safe Probe X)** — 一个开源框架，用于自动化评估智能代理的安全性，提供系统化、可扩展的工具来探测和评估不同环境下的AI安全。

## 概述

Agent Safe Probe 是一个全面的测试框架，旨在评估AI代理系统的安全性和可靠性。它提供了系统化的方法来测试各种攻击场景，包括提示注入、后门攻击、基于记忆的攻击等。

## 功能特性

### 🎯 支持的攻击方法

#### 1. **直接提示注入 (DPI)**
- **简单注入**: 基本的恶意指令注入
- **虚假完成**: 误报完成信号
- **转义字符**: 使用特殊字符绕过过滤器
- **上下文忽略**: 忽略先前上下文的指令
- **组合攻击**: 结合多种技术的多向量攻击

#### 2. **观察提示注入 (OPI)**
- 通过工具观察响应注入恶意指令
- 测试代理处理对抗性观察的能力
- 观察模式下的上下文忽略攻击

#### 3. **仅提示触发 (POT) 后门攻击**
- 植入由特定触发器激活的后门
- 测试代理对基于触发器攻击的脆弱性
- 支持攻击性和非攻击性攻击模式

#### 4. **基于记忆的攻击**
- 通过代理的记忆/上下文搜索进行攻击
- 测试RAG（检索增强生成）系统的脆弱性
- 长期记忆中毒攻击

### 🛡️ 防御策略

- **分隔符防御**: 使用特殊分隔符标记合法输入
- **指令预防**: 添加保护性指令
- **释义防御**: 重新表述用户输入
- **动态提示重写**: 自动提示清理
- **三明治防御**: 用保护性内容包装输入

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/agent-safe-probe-x.git
cd agent-safe-probe-x

# 安装依赖
pip install -r requirements.txt
```

### 设置 Ollama（默认）

本框架默认使用 **Ollama** 运行本地LLM。您需要先安装Ollama并下载模型：

```bash
# 安装 Ollama（如果尚未安装）
# 访问 https://ollama.ai 获取安装说明

# 下载默认模型 (llama3:8b)
ollama pull llama3:8b

# 或下载其他支持的模型：
ollama pull qwen2:7b
ollama pull gemma2:9b
ollama pull llama3.1:8b
```

框架自动使用Ollama作为默认后端。您可以在配置文件中配置要使用的模型。

### 配置

编辑 `config/` 目录下的文件来配置攻击参数。默认设置使用Ollama模型：

```yaml
# config/DPI.yml - 直接提示注入示例
injection_method: direct_prompt_injection
llms:
  - ollama/llama3:8b  # 使用 Ollama 模型
attack_types:
  - naive
  - fake_completion
  - escape_characters

# 后端配置
use_backend: ollama
eval_device: cuda
max_gpu_memory: '{"0": "20GiB"}'
```

**注意**: 确保在运行攻击之前已下载Ollama模型。对您要使用的每个模型运行 `ollama pull <model_name>`。

### 运行攻击

```bash
# 直接提示注入（默认使用 Ollama）
python main_attacker.py --config config/DPI.yml

# 观察提示注入
python main_attacker.py --config config/OPI.yml

# POT 后门攻击
python main_attacker.py --config config/POT.yml

# 基于记忆的攻击
python main_attacker.py --config config/MP.yml --read_db --memory_attack
```

**运行前**: 确保Ollama已安装且所需模型已下载。当模型名称以 `ollama/` 开头时，框架将自动使用Ollama后端。

## 项目结构

```
agent-safe-probe-x/
├── main_attacker.py          # 主攻击运行器
├── config/                    # 配置文件
│   ├── DPI.yml               # 直接提示注入
│   ├── OPI.yml               # 观察提示注入
│   ├── POT.yml               # 仅提示触发的后门
│   └── mixed.yml             # 混合攻击场景
├── data/                      # 数据文件
│   ├── agent_task.jsonl       # 代理任务定义
│   ├── all_attack_tools.jsonl # 攻击工具定义
│   └── all_normal_tools.jsonl # 正常工具定义
├── pyopenagi/                 # 代理框架
│   └── agents/                # 代理实现
├── aios/                      # AIOS 组件
│   ├── llm_core/             # LLM 集成
│   ├── scheduler/            # 任务调度
│   └── memory/               # 记忆管理
├── memory_defense/            # 防御评估工具
└── logs/                      # 攻击日志和结果
```

## 支持的 LLM

本框架支持多种LLM后端：

### 本地模型（Ollama - 默认）
- **llama3:8b** - Meta的Llama 3（80亿参数）
- **llama3.1:8b** - Meta的Llama 3.1（80亿参数）
- **qwen2:7b** - 阿里云的Qwen2（70亿参数）
- **gemma2:9b** - Google的Gemma 2（90亿参数）
- 以及更多Ollama兼容模型

### 云端模型（可选）
- OpenAI GPT-4, GPT-3.5-turbo
- Anthropic Claude 3.5 Sonnet
- Google Gemini

**注意**: 云端模型需要API密钥。默认情况下，框架使用Ollama进行本地执行，无需API依赖。

## 支持的代理

本框架包含预配置的代理，用于测试各种领域：

- **学术代理**: 研究和学术任务
- **金融分析师代理**: 金融分析和投资建议
- **法律顾问代理**: 法律咨询和文件分析
- **医学顾问代理**: 医学信息和健康建议
- **系统管理员代理**: 系统管理任务
- **电子商务经理代理**: 电子商务运营
- **教育顾问代理**: 教育指导
- **自动驾驶代理**: 自动驾驶车辆控制
- **航空航天工程师代理**: 航空航天工程任务
- **心理咨询师代理**: 心理健康咨询

## 攻击工具

本框架包含全面的攻击工具库，用于测试各种恶意场景：

- **资源劫持**: 未经授权的资源分配
- **凭据收集**: 密码和凭据窃取
- **数据泄露**: 未经授权的数据导出
- **系统监控**: 未经授权的监控
- **权限提升**: 未经授权的访问提升
- **进程注入**: 将代码注入到合法进程中
- **以及更多...**

完整列表请参见 `data/all_attack_tools.jsonl`。

## 结果分析

框架输出详细结果，包括：

- **攻击成功率**: 成功攻击的百分比
- **原始任务完成率**: 合法任务是否仍然有效
- **记忆搜索成功率**: RAG系统的有效性
- **拒绝率**: 代理拒绝恶意请求的能力
- **响应合规性**: 基于LLM的合规性评估

结果保存为CSV文件以供进一步分析。

## 研究应用

本框架适用于：

- **安全研究人员**: 测试代理脆弱性
- **AI安全研究人员**: 评估安全机制
- **渗透测试人员**: 对AI系统进行红队演练
- **防御开发人员**: 构建健壮的代理

## 贡献

欢迎贡献！请参阅我们的贡献指南。

## 许可证

MIT License - 详见 LICENSE 文件。

## 引用

如果您在研究中使用了Agent Safe Probe，请引用：

```bibtex
@software{agent_safe_probe,
  title = {Agent Safe Probe (ASP-X): An Open-Source Framework for AI Agent Safety Evaluation},
  author = {Shi, Yumeng and Zhang, Qingyun},
  year = {2025},
  license = {MIT},
  url = {https://github.com/yourusername/agent-safe-probe-x}
}
```

## 联系方式

如有问题、建议或反馈，请在GitHub上提交issue。

## 系统要求

- Python 3.8+
- Ollama（用于默认本地模型执行）
- 推荐使用GPU（以获得更快的推理速度）
- CUDA工具包（用于GPU加速）

## 免责声明

本框架仅用于合法的安全研究和授权测试。用户在使用本软件测试任何系统之前，有责任确保获得适当的授权。作者对软件的滥用不承担任何责任。
