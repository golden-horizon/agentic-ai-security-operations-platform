import ollama

response = ollama.chat(
    model="qwen2.5:3b",
    messages=[
        {"role": "system", "content": "You are a helpful SOC analyst assistant."},
        {"role": "user", "content": "Explain brute force attack in simple words."}
    ]
)

print(response["message"]["content"])