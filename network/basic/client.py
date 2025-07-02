import json
import socket
import time
import base64
import random
import threading
import sys
import unicodedata
from rich.console import Console

console = Console()

# ---------------------------
# Load configuration from JSON
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
# PAYLOAD DEFINITIONS
# ---------------------------
payloads = {
    "Payload 0001: Control Characters": '\u0001\u0002\u0003\u0003\u0004\u0005\u0006\u0007\u0008\u0009',
    "Payload 0002: Arabic Characters": '\u0610\u0611\u0612\u0613\u0614\u0615',
    "Payload 0003: Thai Characters": '\u1714\u1734\u1772\u1773',
    "Payload 0004: Limbu Characters": '\u1927\u1928\u1929\u1930\u1931\u1932\u1933\u1934\u1934\u1935\u1936\u1937',
    "Payload 0005: Cyrillic Characters": '\u0483\u0484\u0485\u0486\u0487\u0488\u0489',
    "Payload 0006: Test Payload 0001": '\u14ED\u0021\u00A1\u254E',
    "Payload 0007: Test Payload 0002": '\u0020\u200D\u0009',
    "Payload 0008: Test Payload 0003": '\u28CE\u2847\uA27A\u10DA\u0F3D\u0B87\u2022\u031B\u0029\u0F80\u25DE\u0F0E\u0EB6\u09E3\u09E2\u0F80\u061E\u0616\u002D\u30FB\u2727\u0028\u0E51\u0D95\u0E31\u0DC5\u002A\u0F80\u002E\u3002\u0308\u00B0',
    "Payload 0009: Test Payload 0004": '\u3000\u031F\u031E\u031D\u031C\u0319\u0318\u0317\u0316\u0489\u0335\u0334\u0328\u0327\u0322\u0321\u033C\u033B\u033A\u0339\u0333\u0332\u0331\u0330\u032F\u032E\u032D\u032C\u032B\u032A\u0329\u0326\u0325\u0324\u0323\u0320\u0488\u0348\u0347\u0349\u034D\u034E\u0353\u0354\u0355\u0356\u0359\u035A\u035C\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0362\u0345',
    "Default Payload Raw": '\u1927\u1928\u1929\u1930\u1931\u1932\u1933\u1934\u1934\u1935\u1936\u1937',
    "Unicode Overflow Payload": '\u0610\u0611\u0612\u0613\u0614\u0615' * 1024,
    "Example Payload 001": "\n" + ('\u0610\u0611\u0612\u0613\u0614\u0615' * 1024),
    "Original UTF-8 Payload": "Hello, world!",
    "Original Japanese Payload": "こんにちは",
    "Original Cyrillic Payload": "Привет",
    "Original Chinese Payload": "你好",
    "Original Raw Bytes Payload": b'\x00\xFF\xAB\xCD'
}

# ---------------------------
# Base Mutation Functions (Existing)
# ---------------------------
def ensure_bytes(payload):
    """Ensure payload is of type bytes."""
    if isinstance(payload, bytes):
        return payload
    return payload.encode('utf-8', errors='replace')

def bitwise_flip(payload):
    """Flip all bits in each byte."""
    b = ensure_bytes(payload)
    return bytes(byte ^ 0xFF for byte in b)

def null_injection(payload):
    """Insert a null byte after each byte."""
    b = ensure_bytes(payload)
    return b''.join(bytes([byte, 0]) for byte in b)

def mix_encoding(payload):
    """Encode half the payload in UTF-8 and half in UTF-16."""
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='replace')
    half = len(payload) // 2
    part1 = payload[:half].encode('utf-8', errors='replace')
    part2 = payload[half:].encode('utf-16', errors='replace')
    return part1 + part2

def base64_encode(payload):
    """Return a Base64-encoded byte string of payload."""
    b = ensure_bytes(payload)
    return base64.b64encode(b)

def zalgo_mutation(payload, intensity=None):
    """Add random combining diacritical marks (Zalgo) after each non-space character."""
    if intensity is None:
        intensity = config.get("mutation_intensity", {}).get("zalgo", 3)
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='replace')
    combining = [chr(i) for i in range(0x0300, 0x036F + 1)]
    result = ""
    for char in payload:
        result += char
        if not char.isspace():
            n = random.randint(1, intensity)
            for _ in range(n):
                result += random.choice(combining)
    return result.encode('utf-8', errors='replace')

def arabic_bind(payload):
    """Insert common Arabic diacritics around characters randomly."""
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='replace')
    arabic_diacritics = ['\u064B', '\u064C', '\u064D', '\u064E', '\u064F', '\u0650', '\u0651', '\u0652']
    result = ""
    for char in payload:
        if char.isspace():
            result += char
        else:
            mode = random.choice(['prepend', 'append', 'both', 'none'])
            if mode == 'prepend':
                result += random.choice(arabic_diacritics) + char
            elif mode == 'append':
                result += char + random.choice(arabic_diacritics)
            elif mode == 'both':
                result += random.choice(arabic_diacritics) + char + random.choice(arabic_diacritics)
            else:
                result += char
    return result.encode('utf-8', errors='replace')

# ---------------------------
# Additional Mutation Techniques (Points 1-5)
# ---------------------------
def unicode_normalization(payload):
    """
    Normalize the payload using a random Unicode normalization form: NFC, NFD, NFKC, or NFKD.
    """
    forms = ['NFC', 'NFD', 'NFKC', 'NFKD']
    chosen_form = random.choice(forms)
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='replace')
    normalized = unicodedata.normalize(chosen_form, payload)
    return normalized.encode('utf-8', errors='replace')

def emoji_injection(payload):
    """
    Inject random emojis into the payload. Emojis chosen from a preset list are inserted at random positions.
    """
    emojis = ["😀", "🚀", "🔥", "🎉", "💥", "🤖"]
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='replace')
    result = ""
    for char in payload:
        result += char
        if not char.isspace() and random.choice([True, False]):
            result += random.choice(emojis)
    return result.encode('utf-8', errors='replace')

def character_shuffle(payload):
    """
    Shuffle the characters of the payload randomly.
    """
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='replace')
    char_list = list(payload)
    random.shuffle(char_list)
    shuffled = "".join(char_list)
    return shuffled.encode('utf-8', errors='replace')

def control_sequence_injection(payload):
    """
    Insert common ANSI escape sequences into the payload at random positions.
    """
    ansi_sequences = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[0m"]
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8', errors='replace')
    result = ""
    for char in payload:
        if random.choice([True, False]):
            result += random.choice(ansi_sequences)
        result += char
    return result.encode('utf-8', errors='replace')

def invalid_byte_sequence(payload):
    """
    Insert an intentionally invalid overlong UTF-8 sequence or other invalid bytes.
    For example, insert the overlong encoding of '/' (b'\xC0\xAF') into the payload.
    """
    b = ensure_bytes(payload)
    # Insert invalid byte sequence at a random index
    idx = random.randint(0, len(b))
    invalid_seq = b'\xC0\xAF'
    mutated = b[:idx] + invalid_seq + b[idx:]
    return mutated

# ---------------------------
# Build a dictionary of all mutation functions.
# ---------------------------
# These functions can be chained randomly.
available_mutations = {
    "Bitwise Flip": bitwise_flip,
    "Null Injection": null_injection,
    "Mix Encoding": mix_encoding,
    "Base64": base64_encode,
    "Zalgo": zalgo_mutation,
    "Arabic Binding": arabic_bind,
    "Unicode Normalization": unicode_normalization,
    "Emoji Injection": emoji_injection,
    "Character Shuffle": character_shuffle,
    "Control Sequence Injection": control_sequence_injection,
    "Invalid Byte Sequence": invalid_byte_sequence
}

# ---------------------------
# Chain Mutations (Randomly select between chain_min and chain_max mutations)
# ---------------------------
def chain_mutations(payload):
    chain_min = config.get("mutation_chain_min", 1)
    chain_max = config.get("mutation_chain_max", 3)
    n = random.randint(chain_min, chain_max)
    # Randomly sample n mutation functions (if n exceeds available, sample with replacement)
    funcs = random.sample(list(available_mutations.values()), min(n, len(available_mutations)))
    mutated = payload
    for func in funcs:
        mutated = func(mutated)
    return mutated

# ---------------------------
# Fragmentation Function (already defined)
# ---------------------------
def fragmentation(payload):
    """
    Split payload into fragments (3 parts) to simulate network-level fragmentation.
    """
    b = ensure_bytes(payload)
    frag_size = max(1, len(b) // 3)
    return [b[i:i+frag_size] for i in range(0, len(b), frag_size)]

# ---------------------------
# Sending Functions (Client Side)
# ---------------------------
def send_payload(payload_bytes, label):
    """Send a byte payload to target host/port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((config["target_host"], config["target_port"]))
        console.print(f"[bold yellow]Sending [{label}] with {len(payload_bytes)} bytes...[/bold yellow]")
        s.sendall(payload_bytes)
        s.close()
    except Exception as e:
        console.print(f"[red]Error sending [{label}]: {e}[/red]")

def send_fragmented(payload, label):
    """Send payload in fragments with a delay between fragments."""
    frags = fragmentation(payload)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((config["target_host"], config["target_port"]))
        console.print(f"[bold yellow]Sending Fragmented [{label}] in {len(frags)} fragments...[/bold yellow]")
        for i, frag in enumerate(frags, start=1):
            s.sendall(frag)
            console.print(f"  [cyan]Fragment {i}/{len(frags)}: {len(frag)} bytes[/cyan]")
            time.sleep(config.get("fragment_delay", 0.1))
        s.close()
    except Exception as e:
        console.print(f"[red]Error sending fragmented [{label}]: {e}[/red]")

# ---------------------------
# Fuzzer Worker Function (each thread runs this)
# ---------------------------
def fuzzer_worker(thread_id):
    # Set a unique seed per thread for variability.
    random.seed(time.time() + thread_id)
    iterations = config.get("iterations", 1)
    for it in range(iterations):
        console.print(f"[bold green]Thread {thread_id} - Starting iteration {it+1}/{iterations}...[/bold green]")
        for payload_name, payload in payloads.items():
            # Decide whether to use mutation chaining or send original payload.
            if config.get("use_mutations", True):
                mutated_payload = chain_mutations(payload)
            else:
                mutated_payload = ensure_bytes(payload)
            label = f"{payload_name} - Mutated Chain"
            send_payload(mutated_payload, label)
            time.sleep(config.get("packet_delay", 0.3))
            if config.get("use_fragmentation", True):
                send_fragmented(payload, f"{payload_name} - Fragmentation")
                time.sleep(config.get("packet_delay", 0.3))
        console.print(f"[bold green]Thread {thread_id} - Iteration {it+1} complete.[/bold green]")

# ---------------------------
# MAIN: Start threads and run fuzzer
# ---------------------------
def run_fuzzer():
    thread_count = config.get("thread_count", 1)
    threads = []
    for i in range(thread_count):
        t = threading.Thread(target=fuzzer_worker, args=(i+1,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    console.print("[bold green][✓] All mutated payloads sent successfully![/bold green]")

if __name__ == "__main__":
    run_fuzzer()