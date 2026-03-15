"""Unit tests for create_stacktrace."""

import pytest

from server import create_stacktrace


def test_empty_entries_returns_no_stacktrace_found():
    assert create_stacktrace({}) == "No stacktrace found"
    assert create_stacktrace({"entries": []}) == "No stacktrace found"


def test_entries_without_exception_type_skipped():
    event = {"entries": [{"type": "message", "data": {}}]}
    assert create_stacktrace(event) == "No stacktrace found"


def test_exception_entry_with_frames():
    event = {
        "entries": [
            {
                "type": "exception",
                "data": {
                    "values": [
                        {
                            "type": "ValueError",
                            "value": "invalid value",
                            "stacktrace": {
                                "frames": [
                                    {
                                        "filename": "app.py",
                                        "lineNo": 10,
                                        "function": "main",
                                    },
                                    {
                                        "filename": "main.py",
                                        "lineno": 5,
                                        "function": "run",
                                    },
                                ]
                            },
                        }
                    ]
                },
            }
        ]
    }
    result = create_stacktrace(event)
    assert "ValueError" in result
    assert "invalid value" in result
    assert "app.py:10 in main" in result
    assert "main.py:5 in run" in result
    assert "Stacktrace:" in result


def test_exception_entry_with_context_lines():
    event = {
        "entries": [
            {
                "type": "exception",
                "data": {
                    "values": [
                        {
                            "type": "TypeError",
                            "value": "None",
                            "stacktrace": {
                                "frames": [
                                    {
                                        "filename": "foo.py",
                                        "lineNo": 42,
                                        "function": "bar",
                                        "context": [[10, "  x = 1"], [11, "  y = x + 1"]],
                                    }
                                ]
                            },
                        }
                    ]
                },
            }
        ]
    }
    result = create_stacktrace(event)
    assert "TypeError" in result
    assert "foo.py:42 in bar" in result
    assert "  x = 1" in result
    assert "  y = x + 1" in result


def test_fallback_exception_direct():
    event = {
        "exception": {
            "values": [
                {"type": "RuntimeError", "value": "something broke"},
            ]
        }
    }
    result = create_stacktrace(event)
    assert "RuntimeError" in result
    assert "something broke" in result


def test_fallback_no_values_in_entries():
    event = {"entries": [{"type": "exception", "data": {"values": []}}]}
    result = create_stacktrace(event)
    assert result == "No stacktrace found"