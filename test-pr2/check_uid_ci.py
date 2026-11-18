"""CI check of faf-uid builds made with the repo's EXAMPLE key.

Prints field names only, never machine values: CI logs are public.

usage:
  check_uid_ci.py key-bytes <CMakeCache.txt> <CMakeLists.txt>
      the key bytes CMake got are the example key's (the CMakeLists default)
  check_uid_ci.py check <example private key> <session>=<output file>...
      each output decrypts to well-formed JSON with its session, and the
      machine fields are the same in every output
  check_uid_ci.py compare <example private key> <session> <output a> <output b>
      two builds run on one machine with one session send the server the
      same fields, value types and values; says whether the JSON text differs
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def key_bytes(cache_path, lists_path):
    with open(cache_path, encoding="utf-8") as f:
        got = re.search(r"^UID_PUBKEY_BYTES:[A-Z]*=(.*)$", f.read(), re.M)
    with open(lists_path, encoding="utf-8") as f:
        want = re.search(r'"(200,172[0-9,]*)"', f.read())
    if not got or not got.group(1).strip():
        fail("CMake got no UID_PUBKEY_BYTES")
    if not want or got.group(1).strip() != want.group(1):
        fail("UID_PUBKEY_BYTES is not the example key")
    print("UID_PUBKEY_BYTES: the example key, as expected")


def decrypt(key, path):
    with open(path, "rb") as f:
        raw = f.read().strip()
    if not raw:
        fail(f"{path}: empty output")
    outer = base64.b64decode(raw, validate=True)
    pad, inner = outer[0], outer[1:].decode("ascii")
    if len(inner) <= 24 + 344:
        fail(f"{path}: too short")
    iv = base64.b64decode(inner[:24], validate=True)
    rsa = base64.b64decode(inner[-344:], validate=True)
    body = base64.b64decode(inner[24:-344], validate=True)
    if len(iv) != 16 or len(rsa) != 256 or not body or len(body) % 16:
        fail(f"{path}: bad layout")
    with tempfile.TemporaryDirectory() as tmp:
        rsa_path = os.path.join(tmp, "rsa")
        with open(rsa_path, "wb") as f:
            f.write(rsa)
        aes_key = subprocess.run(
            ["openssl", "pkeyutl", "-decrypt", "-inkey", key,
             "-pkeyopt", "rsa_padding_mode:pkcs1",
             "-pkeyopt", "rsa_pkcs1_implicit_rejection:0", "-in", rsa_path],
            capture_output=True, check=True).stdout
    plain = subprocess.run(
        ["openssl", "enc", "-d", "-aes-128-cbc",
         "-K", aes_key.hex(), "-iv", iv.hex()],
        input=body, capture_output=True, check=True).stdout
    if len(aes_key) != 16 or pad != 16 - len(plain) % 16:
        fail(f"{path}: bad key or pad count")
    text = plain.decode("utf-8")
    if not text.startswith("2"):
        fail(f"{path}: no '2' format prefix")
    return text[1:], json.loads(text[1:])


def flatten(d, prefix=""):
    for k, v in sorted(d.items()):
        if isinstance(v, dict):
            yield from flatten(v, prefix + k + ".")
        else:
            yield prefix + k, v


def check(key, pairs):
    machines = []
    for pair in pairs:
        session, _, path = pair.partition("=")
        _, data = decrypt(key, path)
        if data.get("session") != session:
            fail(f"{path}: wrong session")
        machines.append(data["machine"])
        print(f"ok  {path}: well-formed, session {session}")
    fields = list(flatten(machines[0]))
    print("set:     " + " ".join(n for n, v in fields if v != "invalid"))
    print("invalid: " + " ".join(n for n, v in fields if v == "invalid"))
    if any(m != machines[0] for m in machines[1:]):
        fail("machine fields differ between the outputs")
    print(f"machine fields identical across {len(machines)} output(s)")


def compare(key, session, path_a, path_b):
    text_a, data_a = decrypt(key, path_a)
    text_b, data_b = decrypt(key, path_b)
    for path, data in ((path_a, data_a), (path_b, data_b)):
        if data.get("session") != session:
            fail(f"{path}: wrong session")
    a, b = dict(flatten(data_a)), dict(flatten(data_b))
    if a.keys() != b.keys():
        fail(f"fields differ: only in {path_a}: {sorted(a.keys() - b.keys())}, "
             f"only in {path_b}: {sorted(b.keys() - a.keys())}")
    types = [n for n in a if type(a[n]) is not type(b[n])]
    if types:
        fail(f"value types differ: {types}")
    values = [n for n in a if a[n] != b[n]]
    if values:
        fail(f"values differ: {values}")
    print(f"same {len(a)} fields, same value types ({sorted({type(v).__name__ for v in a.values()})}), same values")
    print("JSON text identical" if text_a == text_b else "JSON text differs, in formatting only")


if len(sys.argv) >= 4 and sys.argv[1] == "key-bytes":
    key_bytes(sys.argv[2], sys.argv[3])
elif len(sys.argv) >= 4 and sys.argv[1] == "check":
    check(sys.argv[2], sys.argv[3:])
elif len(sys.argv) == 6 and sys.argv[1] == "compare":
    compare(*sys.argv[2:])
else:
    fail(__doc__)
