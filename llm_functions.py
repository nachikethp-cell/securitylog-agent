import os
import socket
import sys
import subprocess
import time
from pathlib import Path

import aisuite as ai

# Print fields of response struct 
def print_llm_response(response):
    """
    Prints key fields from an aisuite response object in a readable format.
    """
    print("-" * 30)
    print(f"MODEL USED:   {response.model}")
    print(f"RESPONSE ID:  {response.id}")

    # Navigate the 'choices' list (usually contains 1 item)
    if response.choices:
        choice = response.choices[0]
        print(f"FINISH REASON: {choice.finish_reason}")

        # Print the text content
        content = choice.message.content
        print(f"\nTEXT CONTENT:\n{content}")

        # Check for Tool Calls (important for MCP)
        if hasattr(choice.message, 'tool_calls') and choice.message.tool_calls:
            print("\nTOOL CALLS DETECTED:")
            for tool in choice.message.tool_calls:
                print(f" - Function: {tool.function.name}")
                print(f" - Args:     {tool.function.arguments}")

    print("-" * 30)

def llm_token_usage(response):
   # Print Token Usage
    if hasattr(response, 'usage') and response.usage:
        print("\nUSAGE STATS:")
        print(f" - Prompt Tokens:     {response.usage.prompt_tokens}")
        print(f" - Completion Tokens: {response.usage.completion_tokens}")
        print(f" - Total Tokens:      {response.usage.total_tokens}")

# Print intermediate messages returned by LLM
def print_intermediate_msgs(response):
    """
    Prints intermediate messages from LLM query
    """
    print("\n" + "+"*60)
    print("Tool Call History:")
    print("="*60)
    for msg in response.choices[0].intermediate_messages:
        if msg.role == "assistant" and msg.tool_calls:
            for tool_call in msg.tool_calls:
                print(f"\nTool: {tool_call.function.name}")
                print(f"Arguments: {tool_call.function.arguments}")
        elif msg.role == "tool":
            print(f"Result: {msg.content[:200]}...")



