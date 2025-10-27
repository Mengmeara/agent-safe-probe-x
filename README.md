# Agent Safe Probe (ASP-X)

<div align="center">

**ASP-X (Agent Safe Probe X)** — An open-source framework for automated safety evaluation of intelligent agents

[English](README_EN.md) | [中文](README_CN.md)

</div>

---

## 🌐 Choose Your Language / 选择语言

> **English**: Read the [full English documentation](README_EN.md)  
> **中文**: 阅读 [完整中文文档](README_CN.md)

---

## Quick Overview / 快速概览

**Agent Safe Probe** is a comprehensive testing framework designed to evaluate the security and safety of AI agent systems. It provides a systematic approach to test various attack scenarios including prompt injection, backdoor attacks, memory-based attacks, and more.

**Agent Safe Probe** 是一个全面的测试框架，旨在评估AI代理系统的安全性和可靠性。它提供了系统化的方法来测试各种攻击场景，包括提示注入、后门攻击、基于记忆的攻击等。

### ✨ Key Features / 主要特性

| Feature / 特性 | English / 英文 | 中文 |
|---|---|---|
| 🎯 Attack Methods | Direct/Observation Prompt Injection, Backdoor, Memory-based | 直接/观察提示注入、后门、基于记忆 |
| 🛡️ Defense Strategies | Delimiters, Instruction, Paraphrase, Dynamic Rewriting | 分隔符、指令、释义、动态重写 |
| 🤖 Supported Models | Llama3, Qwen2, Gemma2, GPT-4, Claude, and more | Llama3、Qwen2、Gemma2、GPT-4、Claude等 |
| 🔧 Easy Setup | Ollama integration (default) | Ollama集成（默认） |

### 🚀 Quick Start / 快速开始

```bash
# Clone the repository / 克隆仓库
git clone https://github.com/yourusername/agent-safe-probe-x.git
cd agent-safe-probe-x

# Install dependencies / 安装依赖
pip install -r requirements.txt

# Install Ollama models / 安装 Ollama 模型
ollama pull llama3:8b

# Run attacks / 运行攻击
python main_attacker.py --config config/DPI.yml
```

### 📖 Full Documentation / 完整文档

- **[English Documentation (README_EN.md)](README_EN.md)** - Complete guide with all features, examples, and API references
- **[中文文档 (README_CN.md)](README_CN.md)** - 包含所有功能、示例和API参考的完整指南

### 🎯 Use Cases / 应用场景

- **Security Research** / 安全研究: Testing agent vulnerabilities
- **AI Safety** / AI安全: Evaluating safety mechanisms  
- **Penetration Testing** / 渗透测试: Red teaming AI systems
- **Defensive Development** / 防御开发: Building robust agents

### 📊 Supported Methods / 支持的方法

#### Attack Methods / 攻击方法
- Direct Prompt Injection (DPI) / 直接提示注入
- Observation Prompt Injection (OPI) / 观察提示注入
- Prompt-Only Triggered (POT) Backdoor / 仅提示触发的后门
- Memory-Based Attacks / 基于记忆的攻击

#### Defense Methods / 防御方法
- Delimiters Defense / 分隔符防御
- Instructional Prevention / 指令预防
- Paraphrase Defense / 释义防御
- Dynamic Prompt Rewriting / 动态提示重写
- Sandwich Defense / 三明治防御

### 🤝 Contributing / 贡献

We welcome contributions! See our contributing guidelines.

欢迎贡献！请参阅贡献指南。

### 📄 License / 许可证

MIT License - See [LICENSE](LICENSE) file for details.

MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

### 📞 Contact / 联系方式

For questions or issues, please open an issue on GitHub.

如有问题，请在GitHub上提交issue。

### ⚠️ Disclaimer / 免责声明

This framework is intended solely for legitimate security research and authorized testing.

本框架仅用于合法的安全研究和授权测试。