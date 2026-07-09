import os, sys, json
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import ollama_client

def _mock_response(text: str):
    mock = MagicMock()
    mock.json.return_value = {"response": text}
    mock.raise_for_status = MagicMock()
    return mock

def test_generate_returns_text():
    with patch("ollama_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response("hello")
        client = ollama_client.OllamaClient(base_url="http://localhost:11434", model="test")
        result = client.generate("say hello")
        assert result == "hello"

def test_generate_passes_correct_payload():
    with patch("ollama_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response("x")
        client = ollama_client.OllamaClient(base_url="http://localhost:11434", model="mymodel")
        client.generate("my prompt")
        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["model"] == "mymodel"
        assert payload["prompt"] == "my prompt"
        assert payload["stream"] is False

def test_retries_on_connection_error():
    import requests as req
    with patch("ollama_client.requests.post", side_effect=req.exceptions.ConnectionError) as mock_post:
        client = ollama_client.OllamaClient(base_url="http://localhost:11434", model="x", max_retries=2)
        result = client.generate("prompt")
        assert result is None
        assert mock_post.call_count == 2

def test_returns_none_on_timeout():
    import requests as req
    with patch("ollama_client.requests.post", side_effect=req.exceptions.Timeout):
        client = ollama_client.OllamaClient(base_url="http://localhost:11434", model="x", max_retries=1)
        result = client.generate("prompt")
        assert result is None
