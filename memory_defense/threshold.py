import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import numpy as np

import re
import os
import json

def process_log_clean(log_file):
    memorys = []
    poison_labels = []
    with open(log_file, 'r', encoding='utf-8') as file:
        log_data = file.read()
    # 1. Separate each block marked by "**********************************"
    blocks = log_data.split('**********************************')
    for i, block in enumerate(blocks, 1):
        if i == 0 or i%2==1:
            continue

        pattern = re.compile(
            r'''The workflow generated for the problem is.*?(\[\{.*?\}\])''',
            re.DOTALL
        )

        # Find all matches
        matches = pattern.findall(block)
        # print(f"Block {i} - Number of matches: {len(matches)}")
        # Print the extracted JSON part (i.e., workflow content)
        generated_plan = matches[0]
        print(generated_plan)
        memorys.append(generated_plan)
        poison_labels.append(False)

    return memorys

def parse_plans(plans_json_strs):
    """
    Parse workflow JSON strings into text format.

    Args:
    - plans_json_strs: List of workflow JSON strings.

    Returns:
    - plans_texts: List of parsed workflow texts.
    """
    plans_texts = []
    for json_str in plans_json_strs:
        # Replace single quotes with double quotes to match JSON format
        json_str_fixed = json_str.replace("'", '"')
        try:
            plan_list = json.loads(json_str_fixed)
            # Extract 'message' field from each step and join into text
            plan_text = ' '.join([step['message'] for step in plan_list])
            plans_texts.append(plan_text)
        except json.JSONDecodeError as e:
            print(f'Error decoding JSON: {e}')
            continue

    print(f'Total plans converted to text: {len(plans_texts)}')
    return plans_texts

class PerplexityFilter:
    """
    Calculate text perplexity using Hugging Face models.

    Args:
    - model: Loaded language model.
    - tokenizer: Tokenizer corresponding to the model.
    - threshold: Perplexity threshold.
    - window_size: Sliding window size, default 'all'.

    Methods:
    - detect(sequence): Determine if text passes the perplexity filter.
    - get_log_prob(sequence): Get the log probability (NLL) of text.
    - filter(sequences): Calculate NLL for a group of texts and determine if they pass the filter.
    - filter_window(sequences): Filter text using sliding window.
    """
    def __init__(self, model, tokenizer, threshold, window_size='all'):
        self.tokenizer = tokenizer
        self.model = model.cuda()  # Ensure model runs on GPU
        self.threshold = threshold
        self.window_threshold = threshold
        self.window_size = window_size
        self.cn_loss = torch.nn.CrossEntropyLoss(reduction='none')

    def detect(self, sequence):
        if self.window_size == 'all':
            return (not self.filter([sequence])[-1][0])
        elif self.window_size <= 0 or type(self.window_size) != int:
            raise ValueError(f"ERROR: window_size={self.window_size}. window_size must be a positive integer.")
        return (not self.filter_window([sequence])[-1][0])

    def get_log_prob(self, sequence):
        input_ids = self.tokenizer.encode(sequence, return_tensors='pt').cuda()
        with torch.no_grad():
            logits = self.model(input_ids, labels=input_ids, use_cache=False).logits
        logits = logits[:, :-1, :].contiguous()
        input_ids = input_ids[:, 1:].contiguous()
        log_probs = self.cn_loss(logits.view(-1, logits.size(-1)), input_ids.view(-1))
        return log_probs

    def filter(self, sequences):
        filtered_log_ppl = []
        passed_filter = []
        for sequence in sequences:
            log_probs = self.get_log_prob(sequence)
            NLL_by_token = log_probs
            if NLL_by_token.mean() <= self.threshold:
                passed_filter.append(True)
                filtered_log_ppl.append(NLL_by_token.mean().item())
            else:
                passed_filter.append(False)
                filtered_log_ppl.append(NLL_by_token.mean().item())
        # print(filtered_log_ppl, passed_filter)
        return filtered_log_ppl, passed_filter

    def filter_window(self, sequences, reverse=False):
        filtered_log_ppl_by_window = []
        passed_filter_by_window = []
        passed = []
        for sequence in sequences:
            sequence_window_scores = []
            passed_window_filter = []
            log_probs = self.get_log_prob(sequence)
            NLL_by_token = log_probs
            for i in np.arange(0, len(NLL_by_token), self.window_size):
                if not reverse:
                    window = NLL_by_token[i:i+self.window_size]
                else:
                    if i == 0:
                        window = NLL_by_token[-self.window_size:]
                    elif -(-i-self.window_size) > len(NLL_by_token) and i != 0:
                        window = NLL_by_token[:-i]
                    else:
                        window = NLL_by_token[-i-self.window_size:-i]
                if window.mean() <= self.window_threshold:
                    passed_window_filter.append(True)
                    sequence_window_scores.append(window.mean().item())
                else:
                    passed_window_filter.append(False)
                    sequence_window_scores.append(window.mean().item())
            if all(passed_window_filter):
                passed.append(True)
            else:
                passed.append(False)
            passed_filter_by_window.append(passed_window_filter)
            filtered_log_ppl_by_window.append(sequence_window_scores)
        return filtered_log_ppl_by_window, passed_filter_by_window, passed

def calculate_perplexities(plans_texts, model, tokenizer, perplexity_threshold, window_size):
    """
    Calculate perplexity for a given list of texts and return the perplexity for each text and the average perplexity.

    Args:
    - plans_texts: List of texts.
    - model: Loaded language model.
    - tokenizer: Tokenizer corresponding to the model.
    - perplexity_threshold: Perplexity threshold.
    - window_size: Sliding window size.

    Returns:
    - perplexities: List of perplexities for each text.
    - average_perplexity: Average perplexity of all texts.
    """
    # Instantiate PerplexityFilter
    filter = PerplexityFilter(model=model, tokenizer=tokenizer, threshold=perplexity_threshold, window_size=window_size)
    perplexities = []

    for plan_text in plans_texts:
        # Calculate perplexity
        log_ppl, passed_filter_list = filter.filter([plan_text])
        nll = log_ppl[0]
        # Convert NLL to perplexity
        perplexity = torch.exp(torch.tensor(nll)).item()
        perplexities.append(perplexity)
        # print(f"Perplexity for plan: {perplexity}")

    # Calculate average perplexity
    average_perplexity = sum(perplexities) / len(perplexities) if perplexities else 0.0
    print(f'Average Perplexity over plans: {average_perplexity}')
    return perplexities, average_perplexity

def main():
    # Use log file path
    log_base = 'logs/clean/gpt-4o-2024-08-06/no_memory/combined_attack-non-aggressive_.log'
    # Extract workflow JSON strings
    plans_json_strs = process_log_clean(log_base)
    # Parse workflow into text
    # plans_texts = parse_plans(plans_json_strs)
    # Load model and tokenizer
    model_name = 'facebook/opt-2.7b'
    # model_name = 'EleutherAI/gpt-neo-1.3B'

    model = AutoModelForCausalLM.from_pretrained(model_name)
    tokenizer = AutoTokenizer.from_pretrained(model_name, clean_up_tokenization_spaces=False)

    # Define perplexity filter threshold and window size
    perplexity_threshold = 2.0  # Can be adjusted based on task
    window_size = 10  # Optional, for sliding window filtering, or use 'all'

    # Calculate perplexities
    perplexities, average_perplexity = calculate_perplexities(plans_json_strs, model, tokenizer, perplexity_threshold, window_size)
    # Sort perplexity data
    ppl_values_sorted = sorted(perplexities)
    print(f"Perplexity values: {ppl_values_sorted}")
    # Calculate 99th percentile value
    threshold_ppl = np.percentile(ppl_values_sorted, 99)

    print(f"Perplexity threshold with 1% FPR: {threshold_ppl}")
    # print(f"Average Perplexity: {average_perplexity}")
if __name__ == "__main__":
    main()
