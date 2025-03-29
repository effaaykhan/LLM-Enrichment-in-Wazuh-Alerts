#!/usr/bin/env python3
# llm_query.py

import sys
from openai import OpenAI
import json

def query_llm(prompt):
    try:
        client = OpenAI(
            base_url="https://api.novita.ai/v3/openai",
            api_key="YOUR-API-KEY",
        )

        model = "deepseek/deepseek-v3-turbo"
        stream = False
        max_tokens = 256  # Same as original script
        system_content = "Be a helpful assistant"
        temperature = 1
        top_p = 1
        min_p = 0
        top_k = 50
        presence_penalty = 0
        frequency_penalty = 0
        repetition_penalty = 1
        response_format = { "type": "text" }

        chat_completion_res = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": prompt,
                },
                {
                    "role": "user",
                    "content": "",
                }
            ],
            stream=stream,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            presence_penalty=presence_penalty,
            frequency_penalty=frequency_penalty,
            response_format=response_format,
            extra_body={
                "top_k": top_k,
                "repetition_penalty": repetition_penalty,
                "min_p": min_p
            }
        )

        if not stream:
            return chat_completion_res.choices[0].message.content
        else:
            # This branch won't be used in our script but including for completeness
            response_text = ""
            for chunk in chat_completion_res:
                response_text += chunk.choices[0].delta.content or ""
            return response_text

    except Exception as e:
        print(f"Error querying LLM: {str(e)}", file=sys.stderr)
        sys.exit(1)

if _name_ == "_main_":
    if len(sys.argv) < 2:
        print("Usage: python3 llm_query.py \"Your prompt here\"", file=sys.stderr)
        sys.exit(1)

    prompt = sys.argv[1]
    response = query_llm(prompt)
    print(response)
