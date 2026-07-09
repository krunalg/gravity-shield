try:
    from config_local import *
except ImportError:
    pass
from config import *

import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self,
                 base_url: str = OLLAMA_BASE_URL,
                 model: str = OLLAMA_MODEL,
                 timeout: int = OLLAMA_TIMEOUT,
                 max_retries: int = OLLAMA_MAX_RETRIES):
        self._url = f"{base_url}/api/generate"
        self._model = model
        self._timeout = timeout
        self._max_retries = max_retries

    def generate(self, prompt: str) -> Optional[str]:
        """Send prompt to Ollama, return raw response text or None on failure."""
        import json as json_module
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": True,
            "options": {
                "temperature": 0.1,
                "num_predict": 150,
            }
        }
        for attempt in range(self._max_retries):
            try:
                resp = requests.post(self._url, json=payload, timeout=self._timeout, stream=True)
                resp.raise_for_status()
                full_response = ""
                for line in resp.iter_lines():
                    if line:
                        chunk = json_module.loads(line)
                        full_response += chunk.get("response", "")
                        if chunk.get("done"):
                            break
                return full_response
            except requests.exceptions.Timeout:
                logger.warning(f"Ollama timeout on attempt {attempt + 1}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Ollama connection error on attempt {attempt + 1}")
            except Exception as e:
                logger.error(f"Ollama unexpected error: {e}")
                break
            if attempt < self._max_retries - 1:
                time.sleep(1)
        return None

    def is_available(self) -> bool:
        """Health check — returns True if Ollama is running."""
        try:
            resp = requests.get(
                self._url.replace("/api/generate", "/"),
                timeout=3
            )
            return resp.status_code == 200
        except Exception:
            return False
