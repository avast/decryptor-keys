#!/usr/bin/env python3
"""
Try to decrypt the first 0x180 bytes of troldesh-example-file.xtbl using every
RSA private key found in .txt files under the current directory (recursively).

The main thread walks the directory tree and extracts RSA private keys from
.txt files. Worker threads pull keys from a queue and attempt the RSA
decryption. Number of worker threads = (CPU core count - 2).

Requires: pip install pycryptodome
"""

import os
import queue
import re
import sys
import threading
import time

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
except ImportError:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_v1_5

TEST_ENCRYPTED_FILE = "troldesh-example-file.better_call_saul"
CHUNK_SIZE = 0x180
EXPECTED_PLAINTEXT_LEN = 0x42
TOTAL_KEYS = 750100

PEM_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----",
    re.DOTALL,
)

SENTINEL = b"__DECRYPTION_FAILED__"


def read_target_chunk(path):
    with open(path, "rb") as f:
        return f.read(CHUNK_SIZE)


def find_pem_keys(data):
    return PEM_KEY_RE.findall(data)


def format_elapsed(seconds):
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def print_progress(processed, start_time):
    percent = processed / TOTAL_KEYS * 100
    elapsed = format_elapsed(time.monotonic() - start_time)
    sys.stdout.write(
        f"\r[*] Processed {processed}/{TOTAL_KEYS} keys "
        f"({percent:.2f}%) elapsed {elapsed}")
    sys.stdout.flush()


def rsa_attempt_decrypt(pem, ciphertext):

    # Import RSA key from PEM format
    try:
        key = RSA.import_key(pem)
    except (ValueError, IndexError, TypeError):
        return False, False

    # Check if there is a private key part
    if not key.has_private():
        return True, False

    # Prepare the data to decrypt
    key_len_bytes = key.size_in_bytes()
    if len(ciphertext) >= key_len_bytes:
        ciphertext = ciphertext[:key_len_bytes]

    # Attempt to decrypt using RSA
    try:
        cipher = PKCS1_v1_5.new(key)
        plaintext = cipher.decrypt(ciphertext, SENTINEL)
        if plaintext != SENTINEL and len(plaintext) == EXPECTED_PLAINTEXT_LEN:
            return True, True
    except Exception as e:
        pass
    return True, False


def worker(task_queue, ciphertext, matches, matches_lock, progress, progress_lock, found_event, start_time):

    # Keep working until a proper key is found
    while not found_event.is_set():

        # Pop the task from the queue
        try:
            item = task_queue.get(timeout=0.2)
        except queue.Empty:
            continue

        # Check whether the task is valid
        if item is None:
            task_queue.task_done()
            break

        # Attempt to decrypt the ciphertext
        path, pem = item
        key_is_valid, decryption_ok = rsa_attempt_decrypt(pem, ciphertext)

        # If the key is valid, increment progress
        if key_is_valid is True:
            with progress_lock:
                progress[0] += 1
                print_progress(progress[0], start_time)

        # If the decryption succeeded
        if decryption_ok is True:
            with matches_lock:
                matches.append(os.path.abspath(path))
            found_event.set()

        # Mark the task as done
        task_queue.task_done()


def load_encrypted_file(file_name):

    # Check if the test file exists
    if not os.path.isfile(file_name):
        print(f"[*] Encrypted file not found: '{file_name}'")
        return None
    print(f"[*] Loading file {file_name} ...")

    # Load chunk from the test file
    ciphertext = read_target_chunk(file_name)
    if len(ciphertext) < CHUNK_SIZE:
        print(f"[*] File is too small: {file_name}")
        return None
    print(f"[*] Decrypting file: {file_name} ...")
    return ciphertext


def run_test(test_file, path):

    try:
        ciphertext = load_encrypted_file(test_file)
        if not ciphertext:
            return False

        # Load the PEM file to memory
        with open(path, "rb") as f:
            data = f.read()

        # Enumerate all PEM blocks
        pem_blocks = find_pem_keys(data)
        for pem in pem_blocks:

            # Attempt to decrypt
            key_is_valid, decryption_ok = rsa_attempt_decrypt(pem, ciphertext)
            if key_is_valid and decryption_ok:
                print("[*] Decryption successful.")
                return True

        print("[*] Decryption failed.")

    except Exception as e:
        pass


def main():
    # Check the arguments
    if len(sys.argv) == 1:
        sys.exit("Missing name of the encrypted file.")
    target_file_name = sys.argv[1]

    # Run the test on a known RSA key file
    run_test(TEST_ENCRYPTED_FILE, ".\\keys\\main\\static\\482.txt")

    # Check for presence of the target file
    ciphertext = load_encrypted_file(target_file_name)
    if not ciphertext:
        sys.exit()
    print("[*] Looking for RSA key ...")

    # Configure the multi-threaded queue
    num_workers = max(1, (os.cpu_count() or 1) - 2)
    task_queue = queue.Queue()
    matches = []
    matches_lock = threading.Lock()
    progress = [0]
    progress_lock = threading.Lock()
    found_event = threading.Event()
    start_time = time.monotonic()

    threads = [
        threading.Thread(
            target=worker,
            args=(task_queue, ciphertext, matches, matches_lock,
                  progress, progress_lock, found_event, start_time),
            daemon=True,
        )
        for _ in range(num_workers)
    ]
    for t in threads:
        t.start()

    # Main thread: search the local folder (and subfolders) for keys and
    # hand each one off to the worker pool. Stop early if a worker already
    # found the right key.
    for root, _dirs, files in os.walk("."):
        if found_event.is_set():
            break
        for name in files:
            if found_event.is_set():
                break
            if not name.lower().endswith(".txt"):
                continue
            path = os.path.join(root, name)

            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                continue

            # Search the repository
            pem_blocks = find_pem_keys(data)
            if not pem_blocks:
                continue

            for pem in pem_blocks:
                task_queue.put((path, pem))

    # Push one sentinel per worker so that, if no key ever matched and
    # found_event never gets set, workers still stop once the queue drains
    # instead of blocking forever on task_queue.get().
    for _ in threads:
        task_queue.put(None)

    # Once a worker finds the key it sets found_event, which makes every
    # worker (including any still blocked on task_queue.get) exit its loop.
    for t in threads:
        t.join()

    print()  # move past the progress line
    if matches:
        print("[*] Matching key file(s):")
        for m in matches:
            print(f"    {m}")
    else:
        print("[*] No key successfully decrypted the sample block.")

    print(f"[*] Total keys processed: {progress[0]}")


if __name__ == "__main__":
    main()
