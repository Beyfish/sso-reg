from __future__ import annotations

import socket
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.server import GuiHandler

APP_TITLE = "企业 SSO Codex 控制台"
DEFAULT_HOST = "127.0.0.1"


def find_free_port(host: str = DEFAULT_HOST) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def start_gui_server(host: str = DEFAULT_HOST, port: int | None = None) -> tuple[ThreadingHTTPServer, str]:
    selected_port = port or find_free_port(host)
    httpd = ThreadingHTTPServer((host, selected_port), GuiHandler)
    thread = threading.Thread(target=httpd.serve_forever, name="company-sso-gui-server", daemon=True)
    thread.start()
    return httpd, f"http://{host}:{selected_port}/index.html"


def main() -> int:
    import webview

    httpd, url = start_gui_server()
    try:
        window = webview.create_window(
            APP_TITLE,
            url,
            width=1440,
            height=920,
            min_size=(1180, 720),
            confirm_close=False,
        )
        webview.start(debug=False, private_mode=True)
        return 0 if window else 1
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
