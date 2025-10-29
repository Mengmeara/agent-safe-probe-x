# registering all proprietary llm models in a constant

from .gpt_llm import GPTLLM
from .gemini_llm import GeminiLLM
from .bed_rock import BedrockLLM

# Conditionally import ClaudeLLM to avoid requiring anthropic module
try:
    from .claude_llm import ClaudeLLM
    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False
    ClaudeLLM = None

#used for closed LLM model registry
MODEL_REGISTRY = {
    # Gemini-1.5
    "gemini-1.5-flash": GeminiLLM,
    "gemini-1.5-pro": GeminiLLM,

    # GPT3.5
    'gpt-3.5-turbo': GPTLLM,
    'gpt-4-turbo': GPTLLM,

    # GPT4o
    'gpt-4o': GPTLLM,
    'gpt-4o-2024-08-06': GPTLLM,
    'gpt-4o-mini': GPTLLM,
}

# Add Claude models only if available
if CLAUDE_AVAILABLE:
    MODEL_REGISTRY['claude-3-5-sonnet-20240620'] = ClaudeLLM
    MODEL_REGISTRY['bedrock/anthropic.claude-3-haiku-20240307-v1:0'] = BedrockLLM
