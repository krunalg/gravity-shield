from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import threading
import time
from typing import Optional, Union

import requests

logger = logging.getLogger(__name__)

_REQUEST_LOCK = threading.Lock()


class OllamaClient:
    def __init__(self,
                 base_url: str = OLLAMA_BASE_URL,
                 model: str = OLLAMA_MODEL,
                 timeout: Union[int, tuple[int, int]] = (OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT),
                 max_retries: int = OLLAMA_MAX_RETRIES,
                 num_predict: int = OLLAMA_NUM_PREDICT,
                 temperature: float = OLLAMA_TEMPERATURE):
        self._base_url = base_url.rstrip("/")
        self._url = f"{self._base_url}/api/generate"
        self._model = model
        self._timeout = timeout
        self._max_retries = max_retries
        self._num_predict = num_predict
        self._temperature = temperature

    def generate(self, prompt: str) -> Optional[str]:
        """Send prompt to Ollama, return raw response text or None on failure."""
        import json as json_module
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": True,
            "options": {
                "temperature": self._temperature,
                "num_predict": self._num_predict,
            }
        }
        for attempt in range(self._max_retries):
            try:
                started = time.monotonic()
                logger.debug(
                    "Ollama request attempt %s/%s model=%s prompt_chars=%s timeout=%s",
                    attempt + 1,
                    self._max_retries,
                    self._model,
                    len(prompt),
                    self._timeout,
                )
                with _REQUEST_LOCK:
                    resp = requests.post(self._url, json=payload, timeout=self._timeout, stream=True)
                    resp.raise_for_status()
                    full_response = ""
                    for line in resp.iter_lines():
                        if line:
                            chunk = json_module.loads(line)
                            full_response += chunk.get("response", "")
                            if chunk.get("done"):
                                break
                logger.debug(
                    "Ollama response complete model=%s response_chars=%s elapsed=%.2fs",
                    self._model,
                    len(full_response),
                    time.monotonic() - started,
                )
                return full_response
            except requests.exceptions.Timeout:
                logger.warning(
                    "Ollama timeout on attempt %s/%s model=%s prompt_chars=%s timeout=%s",
                    attempt + 1,
                    self._max_retries,
                    self._model,
                    len(prompt),
                    self._timeout,
                )
            except requests.exceptions.ConnectionError:
                logger.warning(f"Ollama connection error on attempt {attempt + 1}")
            except requests.exceptions.HTTPError as e:
                response = e.response
                status = response.status_code if response is not None else "unknown"
                body = response.text[:300] if response is not None else ""
                logger.error(
                    "Ollama HTTP error %s for model %s at %s: %s",
                    status,
                    self._model,
                    self._url,
                    body,
                )
                break
            except Exception as e:
                logger.error(f"Ollama unexpected error: {e}")
                break
            if attempt < self._max_retries - 1:
                time.sleep(1)
        return None

    def is_available(self) -> bool:
        """Health check — returns True if Ollama is running."""
        try:
            resp = requests.get(f"{self._base_url}/api/tags", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False
