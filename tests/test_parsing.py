import sys
import os
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.parser_engine import ParserEngine

def test_linux_parser():
    parser = ParserEngine()
    log_line = "Mar 10 09:34:21 server1 kernel: [    0.000000] Linux version 5.4.0 (root@build)"
    parsed = parser.parse_log('linux', log_line)
    assert parsed['timestamp'] == "Mar 10 09:34:21"
    assert parsed['host'] == "server1"
    assert parsed['service'] == "kernel"
    assert "Linux version 5.4.0" in parsed['message']

def test_apache_parser():
    parser = ParserEngine()
    log_line = '192.168.1.10 - - [10/Mar/2026:12:34:56 +0000] "GET /index.html HTTP/1.1" 200'
    parsed = parser.parse_log('apache', log_line)
    assert parsed['ip'] == "192.168.1.10"
    assert parsed['time'] == "10/Mar/2026:12:34:56 +0000"
    assert parsed['request'] == "GET /index.html HTTP/1.1"
    assert parsed['status'] == "200"

def test_template_extraction():
    parser = ParserEngine()
    msg = "Failed password for root from 192.168.1.55 on port 22."
    template, template_id = parser.extract_template(msg)
    
    # 192.168.1.55 should be replaced by <*>
    # 22 should be replaced by <*>
    assert "<*>" in template
    assert "192.168.1.55" not in template
