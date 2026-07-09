import os, sys, json
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import ollama_client

def _mock_response(text: str):
    mock = MagicMock()
    mock.iter_lines.return_value = [
        json.dumps({"response": text, "done": False}).encode(),
        json.dumps({"response": "", "done": True}).encode(),
    ]
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
        assert payload["stream"] is True
        assert payload["options"]["temperature"] == 0.1
        assert payload["options"]["num_predict"] == 256
        assert call_kwargs[1]["timeout"] == (ollama_client.OLLAMA_CONNECT_TIMEOUT, ollama_client.OLLAMA_READ_TIMEOUT)

def test_retries_on_connection_error():
    import requests as req
    with patch("ollama_client.requests.post", side_effect=req.exceptions.ConnectionError) as mock_post:
        client = ollama_client.OllamaClient(base_url="http://localhost:11434", model="x", max_retries=2)
        result = client.generate("prompt")
        assert result is None
        assert mock_post.call_count == 2

def test_returns_none_on_timeout(caplog):
    import requests as req
    with patch("ollama_client.requests.post", side_effect=req.exceptions.Timeout):
        client = ollama_client.OllamaClient(base_url="http://localhost:11434", model="x", max_retries=1)
        result = client.generate("prompt")
        assert result is None
    assert "Ollama timeout on attempt 1/1" in caplog.text
    assert "prompt_chars=6" in caplog.text

def test_logs_http_error_body(caplog):
    import requests as req

    response = MagicMock()
    response.status_code = 404
    response.text = '{"error":"model not found"}'
    error = req.exceptions.HTTPError("404 Client Error")
    error.response = response

    with patch("ollama_client.requests.post") as mock_post:
        mock_post.return_value.raise_for_status.side_effect = error
        client = ollama_client.OllamaClient(base_url="http://localhost:11434/", model="missing-model", max_retries=1)
        result = client.generate("prompt")

    assert result is None
    assert "Ollama HTTP error 404" in caplog.text
    assert "missing-model" in caplog.text
    assert "model not found" in caplog.text
