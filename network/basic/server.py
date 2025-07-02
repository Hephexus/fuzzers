import socket
import json
import base64
import sys
import time
from rich.console import Console
from rich.table import Table

console = Console()

# ---------------------------
# Load shared configuration from JSON
# ---------------------------
def load_config(config_path="config_fuzzer_packet.json"):
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)

config = load_config()

# ---------------------------
# Utility: Decode data with a given encoding (handling errors gracefully)
# ---------------------------
def decode_with_endian(data, encoding):
    try:
        return data.decode(encoding, errors="replace")
    except Exception as e:
        return f"Error: {e}"

# ---------------------------
# Main server loop
# ---------------------------
def start_server():
    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_host = config.get("listen_host", "0.0.0.0")
    listen_port = config.get("listen_port", 12345)
    server_socket.bind((listen_host, listen_port))
    server_socket.listen(5)
    console.print(f"[bold green]Listening on {listen_host}:{listen_port}...[/bold green]")
    
    # Accept connections in a loop.
    while True:
        conn, addr = server_socket.accept()
        console.print(f"[bold yellow]Connection from {addr}[/bold yellow]")
        data = b""
        # Read data in chunks until the connection is closed.
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
        
        if data:
            display_received_data(data)
        conn.close()

# ---------------------------
# Display the received data in a rich table with various decodings.
# ---------------------------
def display_received_data(data):
    table = Table(title="Received Data Formats")
    table.add_column("Format", style="cyan", justify="right")
    table.add_column("Value", style="magenta")
    table.add_column("Byte Size", style="yellow")
    
    # 1. Raw Bytes
    table.add_row("Bytes", repr(data), f"{len(data)} bytes")
    
    # 2. Raw Unicode (show each character's Unicode code point)
    try:
        utf8_decoded = data.decode("utf-8", errors="replace")
    except Exception as e:
        utf8_decoded = f"Error: {e}"
    unicode_points = " ".join(f"U+{ord(c):04X}" for c in utf8_decoded)
    table.add_row("Raw Unicode", unicode_points, f"{len(unicode_points.encode('utf-8'))} bytes")
    
    # 3. UTF-8 Interpretation
    table.add_row("UTF-8", utf8_decoded, f"{len(utf8_decoded.encode('utf-8'))} bytes")
    
    # 4. UTF-16 LE and UTF-16 BE
    utf16_le = decode_with_endian(data, "utf-16-le")
    utf16_be = decode_with_endian(data, "utf-16-be")
    table.add_row("UTF-16 LE", utf16_le, f"{len(utf16_le.encode('utf-16-le', errors='replace'))} bytes")
    table.add_row("UTF-16 BE", utf16_be, f"{len(utf16_be.encode('utf-16-be', errors='replace'))} bytes")
    
    # 5. UTF-32 LE and UTF-32 BE
    utf32_le = decode_with_endian(data, "utf-32-le")
    utf32_be = decode_with_endian(data, "utf-32-be")
    table.add_row("UTF-32 LE", utf32_le, f"{len(utf32_le.encode('utf-32-le', errors='replace'))} bytes")
    table.add_row("UTF-32 BE", utf32_be, f"{len(utf32_be.encode('utf-32-be', errors='replace'))} bytes")
    
    # 6. Base64 Decoded
    try:
        decoded_b64 = base64.b64decode(data, validate=True)
        decoded_b64_str = decoded_b64.decode("utf-8", errors="replace")
        b64_size = len(decoded_b64)
    except Exception as e:
        decoded_b64_str = f"Not valid Base64: {e}"
        b64_size = 0
    table.add_row("Base64 Decoded", decoded_b64_str, f"{b64_size} bytes")
    
    console.print(table)

# ---------------------------
# Main entry point
# ---------------------------
if __name__ == "__main__":
    start_server()