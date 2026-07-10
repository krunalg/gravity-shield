import io
import os
import sys
import zipfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from popularity import parse_top_list, fetch_popularity_list


def _zip_bytes(csv_text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top-1m.csv", csv_text)
    return buf.getvalue()


def test_parse_top_list_returns_domain_ranks():
    ranks = parse_top_list("1,google.com\n2,googleapis.com\n3,icicibank.com\n")
    assert ranks == {"google.com": 1, "googleapis.com": 2, "icicibank.com": 3}


def test_parse_top_list_respects_max_rank():
    ranks = parse_top_list("1,google.com\n2,googleapis.com\n3,evil.com\n", max_rank=2)
    assert "evil.com" not in ranks
    assert len(ranks) == 2


def test_parse_top_list_skips_malformed_lines():
    ranks = parse_top_list("notarank,foo.com\n\n1,google.com\n2,nodots\n")
    assert ranks == {"google.com": 1}


def test_fetch_popularity_list_handles_zip():
    resp = MagicMock()
    resp.content = _zip_bytes("1,google.com\n2,googleapis.com\n")
    with patch("popularity.requests.get", return_value=resp):
        ranks = fetch_popularity_list("https://example.test/top-1m.csv.zip", max_rank=10)
    assert ranks == {"google.com": 1, "googleapis.com": 2}


def test_fetch_popularity_list_handles_plain_csv():
    resp = MagicMock()
    resp.content = b"1,google.com\n"
    resp.text = "1,google.com\n"
    with patch("popularity.requests.get", return_value=resp):
        ranks = fetch_popularity_list("https://example.test/top-1m.csv", max_rank=10)
    assert ranks == {"google.com": 1}


def test_fetch_popularity_list_returns_empty_on_error():
    with patch("popularity.requests.get", side_effect=ConnectionError("boom")):
        assert fetch_popularity_list("https://example.test/x.zip", max_rank=10) == {}
