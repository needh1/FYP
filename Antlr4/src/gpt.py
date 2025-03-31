import csv
import json
import logging
import os
import re
import sys
from time import time

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, parent_dir)

from config import working_dir, API_KEY
from src.contract_extractor import (
    extract_function_with_contract, 
    extract_inherited_contracts, 
    extract_imported_contracts, 
    extract_state_variables, 
    extract_modifiers, 
    extract_comments_from_contract, 
    extract_comments_from_function, 
    extract_solc_version, 
    extract_contract, 
    extract_modifier_names
)
from src.micelleneous import read_dataset, get_gpt_template
from src.call_graph_generator import get_callers_callees
from src.gpt_api import chat_with_gpt
from openai import OpenAI
import openai

def print_code(code_lines, gpt_template):
    print('----' * 5)
    print(gpt_template["evidence"]["Role playing"])
    print(gpt_template["evidence"]["code"], "```\n" + code_lines + "\n```")
    return gpt_template["evidence"]["code"] + " ```\n" + code_lines + "\n```\n"

def print_description(description, gpt_template):
    if description:
        print(gpt_template["evidence"]["description"], description)
        return gpt_template["evidence"]["description"] + ' ' + description + '\n'
    return ''

def print_rbac_mechanisms(file, clazz, function, func_or_modi, gpt_template):
    prompt = ''
    did_print = False
    solc_version = extract_solc_version(file)
    if clazz != 'NONE' and clazz != '':
        inherited = extract_inherited_contracts(clazz, file)
        state_vars = extract_state_variables(clazz, file)
        modifiers = extract_modifier_names(file, clazz)
        if inherited:
            prompt += f'{gpt_template["evidence"]["inherited"]} {inherited}.' + '\n'
            did_print = True
        if state_vars:
            prompt += f'{gpt_template["evidence"]["state variables"]} {state_vars}.' + '\n'
            did_print = True
        if modifiers:
            prompt += f'{gpt_template["evidence"]["modifier names"]} {modifiers}. ' + '\n'
            did_print = True
    else:
        modifiers = extract_modifier_names(file, clazz)
        if modifiers:
            prompt += f'{gpt_template["evidence"]["modifier names"]} {modifiers}. \n'
            did_print = True
    if func_or_modi == 'function':
        # Do not search callers for modifiers if not needed.
        state_var_functions, callers, callees = get_callers_callees(file, function, solc_version)
        if callers:
            prompt += "Callers for function" + ' `' + function + '` ' + "are:\n"
            did_print = True
        else:
            prompt += 'This function has no callers.\n'
        if callees:
            prompt += "Callees for function" + ' `' + function + '` ' + "are:" + '\n'
            did_print = True
        else:
            prompt += 'This function has no callees.' + '\n'
        if state_var_functions:
            prompt += f"The functions that use the same state variables as function {function} are:" + '\n'
            for func, src in state_var_functions.items():
                did_print = True
                prompt += func + '\n'
        return prompt, did_print, (state_var_functions, callers, callees)
    return prompt, did_print, ({}, {}, {})

def main_detection():
    # Load GPT template and dataset.
    gpt_template = get_gpt_template()
    dataset = read_dataset(os.path.join(working_dir, 'Data/Dataset.csv'))
    last_index = 0

    for i, name in enumerate(dataset):
        if i < last_index:
            continue
        function = dataset[name]['function']
        if function == '':
            continue
        # Skip if detection result already exists.
        results_path = os.path.join('results_detection', f'{i}_{name}.json')
        if os.path.exists(results_path):
            continue

        timer = time()
        file = dataset[name]['file']
        clazz = dataset[name]['class']
        description = dataset[name]['description']
        code_lines, func_or_modi = extract_function_with_contract(clazz, function, file)

        # Build the initial prompt with code and description.
        first_prompt = ""
        first_prompt += print_code(code_lines, gpt_template)
        first_prompt += print_description(description, gpt_template)

        # Append RBAC-related evidence extracted from the contract.
        rbac_prompt, did_print, context = print_rbac_mechanisms(file, clazz, function, func_or_modi, gpt_template)
        first_prompt += rbac_prompt

        # Append a clear detection question.
        detection_question = """
QUESTION:
Based on the above data, is this function vulnerable due to missing or improper role-based access control (RBAC)?
Please answer with "yes" if it is vulnerable, or "no" if it is not.
Respond with a single word only.

Additional Question:
Is this vulnerability exploitable in practice?
Please answer with "yes" if it is exploitable, or "no" if it is not.

Provide your answers on separate lines, starting with the keyword (YES or NO).
"""
        full_prompt = first_prompt + detection_question

        # Initialize conversation history.
        conversation_history = [{
            "role": "system", 
            "content": gpt_template['evidence']['Role playing']
        }]

        # Call GPT API with the constructed prompt.
        response, conversation_history, token_used = chat_with_gpt(conversation_history, full_prompt, json=False)
        answer = response.strip().lower()
        lines = answer.splitlines()

        if len(lines) >= 2:
            vulnerability_answer = lines[0].split()[0]  # First word of the first line
            exploitable_answer = lines[1].split()[0]      # First word of the second line
        else:
            vulnerability_answer = ""
            exploitable_answer = ""

        print(f"Function: {function}")
        print("Vulnerability Detected?", vulnerability_answer)
        print("Exploitable?", exploitable_answer)
        print("Token usage:", token_used)

        # Save the detection result.
        os.makedirs('results_detection', exist_ok=True)
        with open(results_path, 'w') as f:
            json.dump({
                'id': i,
                'file': file,
                'class': clazz,
                'function': function,
                'description': description,
                'vulnerability_detected': vulnerability_answer,
                'exploitable': exploitable_answer,
                'token_usage': {
                    'prompt_tokens': token_used.prompt_tokens,
                    'completion_tokens': token_used.completion_tokens,
                    'total_tokens': token_used.total_tokens
                },
                'conversation_history': conversation_history,
                'time': time() - timer
            }, f, indent=2)

if __name__ == '__main__':
    main_detection()
