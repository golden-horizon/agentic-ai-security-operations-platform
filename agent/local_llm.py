import ollama

MODEL_NAME = "qwen2.5:3b"


def ask_local_model(prompt: str) -> str:
    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a cybersecurity SOC analyst assistant."},
            {"role": "user", "content": prompt}
        ]
    )

    return response["message"]["content"]