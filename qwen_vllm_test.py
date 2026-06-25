from openai import OpenAI
from vllm_config import VLLM_BASE_URL, VLLM_API_KEY, VLLM_MODEL

client = OpenAI(
    base_url=VLLM_BASE_URL,
    api_key=VLLM_API_KEY
)

response = client.chat.completions.create(
    model=VLLM_MODEL,
    messages=[
        {
            "role": "user",
            "content": "Explain what a brute force attack is in one sentence."
        }
    ]
)

print(response.choices[0].message.content)