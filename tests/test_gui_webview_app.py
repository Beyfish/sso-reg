from __future__ import annotations

from gui.webview_app import DEFAULT_HOST, start_gui_server


def test_webview_app_starts_local_gui_server():
    httpd, url = start_gui_server()
    try:
        host, port = httpd.server_address
        assert host == DEFAULT_HOST
        assert str(port) in url
        assert url.endswith("/index.html")
    finally:
        httpd.shutdown()
        httpd.server_close()
