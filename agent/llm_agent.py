import requests


class LLMAgent:
    """
    Shared base class for agents that need to talk to a local LLM.
    Today it uses Ollama. Later we can change this to vLLM/OpenAI in one place.
    """

    def __init__(
        self,
        model: str = "qwen2.5:3b",
        ollama_url: str = "http://localhost:11434/api/generate",
        timeout: int = 180,
    ):
        self.model = model
        self.ollama_url = ollama_url
        self.timeout = timeout

    def ask_llm(self, prompt: str) -> str:
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=self.timeout,
            )

            response.raise_for_status()
            return response.json()["response"]

        except requests.RequestException as error:
            return f"LLM request failed: {error}"


if __name__ == "__main__":
    agent = LLMAgent()

    result = agent.ask_llm(
        "Explain SQL injection in one short paragraph."
    )

    print("\n=== LLM AGENT TEST ===\n")
    print(result)