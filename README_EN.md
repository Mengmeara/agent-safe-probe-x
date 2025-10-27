# Agent Safe Probe (ASP-X)

**ASP-X (Agent Safe Probe X)** — An open-source framework for automated safety evaluation of intelligent agents, providing systematic, extensible tools for probing and assessing AI safety across diverse environments.

## Overview

Agent Safe Probe is a comprehensive testing framework designed to evaluate the security and safety of AI agent systems. It provides a systematic approach to test various attack scenarios including prompt injection, backdoor attacks, memory-based attacks, and more.

## Features

### 🎯 Supported Attack Methods

#### 1. **Direct Prompt Injection (DPI)**
- **Naive**: Basic injection of malicious instructions
- **Fake Completion**: False positive completion signals
- **Escape Characters**: Using special characters to bypass filters
- **Context Ignoring**: Instructions to ignore previous context
- **Combined Attack**: Multi-vector attack combining multiple techniques

#### 2. **Observation Prompt Injection (OPI)**
- Inject malicious instructions through tool observation responses
- Test agent's ability to handle adversarial observations
- Context ignoring attacks in observation mode

#### 3. **Prompt-Only Triggered (POT) Backdoor Attack**
- Plant backdoors that activate with specific triggers
- Test agent's vulnerability to trigger-based attacks
- Support for aggressive and non-aggressive attack modes

#### 4. **Memory-Based Attack**
- Attack through agent's memory/context search
- Test RAG (Retrieval-Augmented Generation) vulnerabilities
- Long-term memory poisoning attacks

### 🛡️ Defense Strategies

- **Delimiters Defense**: Using special delimiters to mark legitimate input
- **Instructional Prevention**: Adding protective instructions
- **Paraphrase Defense**: Rephrasing user inputs
- **Dynamic Prompt Rewriting**: Automatic prompt sanitization
- **Sandwich Defense**: Wrapping inputs with protective content

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/agent-safe-probe-x.git
cd agent-safe-probe-x

# Install dependencies
pip install -r requirements.txt
```

### Setting Up Ollama (Default)

This framework uses **Ollama** by default for running local LLMs. You need to install Ollama and download the models first:

```bash
# Install Ollama (if not already installed)
# Visit https://ollama.ai for installation instructions

# Download the default model (llama3:8b)
ollama pull llama3:8b

# Or download other supported models:
ollama pull qwen2:7b
ollama pull gemma2:9b
ollama pull llama3.1:8b
```

The framework automatically uses Ollama as the default backend. You can configure which model to use in the config files.

### Configuration

Edit `config/` directory files to configure attack parameters. The default setup uses Ollama models:

```yaml
# config/DPI.yml - Direct Prompt Injection example
injection_method: direct_prompt_injection
llms:
  - ollama/llama3:8b  # Using Ollama model
attack_types:
  - naive
  - fake_completion
  - escape_characters

# Backend configuration
use_backend: ollama
eval_device: cuda
max_gpu_memory: '{"0": "20GiB"}'
```

**Note**: Make sure you have downloaded the Ollama models before running attacks. Run `ollama pull <model_name>` for each model you want to use.

### Running Attacks

```bash
# Direct Prompt Injection (using Ollama by default)
python main_attacker.py --config config/DPI.yml

# Observation Prompt Injection
python main_attacker.py --config config/OPI.yml

# POT Backdoor Attack
python main_attacker.py --config config/POT.yml

# Memory-based Attack
python main_attacker.py --config config/MP.yml --read_db --memory_attack
```

**Before running**: Ensure Ollama is installed and the required models are downloaded. The framework will automatically use the Ollama backend when model names start with `ollama/`.

## Project Structure

```
agent-safe-probe-x/
├── main_attacker.py          # Main attack runner
├── config/                    # Configuration files
│   ├── DPI.yml               # Direct prompt injection
│   ├── OPI.yml               # Observation prompt injection
│   ├── POT.yml               # Prompt-only triggered backdoor
│   └── mixed.yml             # Mixed attack scenarios
├── data/                      # Data files
│   ├── agent_task.jsonl       # Agent task definitions
│   ├── all_attack_tools.jsonl # Attack tool definitions
│   └── all_normal_tools.jsonl # Normal tool definitions
├── pyopenagi/                 # Agent framework
│   └── agents/                # Agent implementations
├── aios/                      # AIOS components
│   ├── llm_core/             # LLM integration
│   ├── scheduler/            # Task scheduling
│   └── memory/               # Memory management
├── memory_defense/            # Defense evaluation tools
└── logs/                      # Attack logs and results
```

## Supported LLMs

The framework supports multiple LLM backends:

### Local Models (Ollama - Default)
- **llama3:8b** - Meta's Llama 3 (8B parameters)
- **llama3.1:8b** - Meta's Llama 3.1 (8B parameters)
- **qwen2:7b** - Alibaba Cloud's Qwen2 (7B parameters)
- **gemma2:9b** - Google's Gemma 2 (9B parameters)
- And more Ollama-compatible models

### Cloud Models (Optional)
- OpenAI GPT-4, GPT-3.5-turbo
- Anthropic Claude 3.5 Sonnet
- Google Gemini

**Note**: Cloud models require API keys. By default, the framework uses Ollama for local execution without API dependencies.

## Supported Agents

The framework includes pre-configured agents for testing across various domains:

- **Academic Agent**: Research and academic tasks
- **Financial Analyst Agent**: Financial analysis and investment advice
- **Legal Consultant Agent**: Legal consultation and document analysis
- **Medical Advisor Agent**: Medical information and health advice
- **System Administrator Agent**: System administration tasks
- **E-commerce Manager Agent**: E-commerce operations
- **Education Consultant Agent**: Educational guidance
- **Autonomous Driving Agent**: Autonomous vehicle control
- **Aerospace Engineer Agent**: Aerospace engineering tasks
- **Psychological Counselor Agent**: Mental health counseling

## Attack Tools

The framework includes a comprehensive library of attack tools testing various malicious scenarios:

- **Resource Hijacking**: Unauthorized resource allocation
- **Credential Harvesting**: Password and credential theft
- **Data Exfiltration**: Unauthorized data export
- **System Monitoring**: Unauthorized surveillance
- **Privilege Escalation**: Unauthorized access elevation
- **Process Injection**: Code injection into legitimate processes
- **And many more...**

See `data/all_attack_tools.jsonl` for the complete list.

## Results Analysis

The framework outputs detailed results including:

- **Attack Success Rate**: Percentage of successful attacks
- **Original Task Completion Rate**: Whether legitimate tasks still work
- **Memory Search Success**: RAG system effectiveness
- **Refusal Rate**: Agent's ability to refuse malicious requests
- **Response Compliance**: LLM-based compliance evaluation

Results are saved to CSV files for further analysis.

## Research Applications

This framework is designed for:

- **Security Researchers**: Testing agent vulnerabilities
- **AI Safety Researchers**: Evaluating safety mechanisms
- **Penetration Testers**: Red teaming AI systems
- **Defensive Developers**: Building robust agents

## Contributing

Contributions are welcome! Please see our contributing guidelines.

## License

MIT License - See LICENSE file for details.

## Citation

If you use Agent Safe Probe in your research, please cite:

```bibtex
@software{agent_safe_probe,
  title = {Agent Safe Probe (ASP-X): An Open-Source Framework for AI Agent Safety Evaluation},
  author = {Shi, Yumeng and Zhang, Qingyun},
  year = {2025},
  license = {MIT},
  url = {https://github.com/yourusername/agent-safe-probe-x}
}
```

## Contact

For questions, issues, or suggestions, please open an issue on GitHub.

## Requirements

- Python 3.8+
- Ollama (for default local model execution)
- GPU recommended (for faster inference)
- CUDA toolkit (for GPU acceleration)

## Disclaimer

This framework is intended solely for legitimate security research and authorized testing. Users are responsible for ensuring they have proper authorization before testing any system. The authors assume no liability for misuse of this software.
