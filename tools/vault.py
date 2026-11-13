import argparse
import hashlib
import hmac
import os
import sys
import zipfile
import zlib

MAGIC = b"CFV1"
SALT_LEN = 16
TAG_LEN = 32
ITERATIONS = 250000
HEADER_LEN = len(MAGIC) + SALT_LEN + TAG_LEN


class VaultError(Exception):
    pass


def _password_bytes(password):
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)


def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha512", _password_bytes(password), salt, ITERATIONS, 64)


def keystream_xor(data, key):
    stream = hashlib.shake_256(key).digest(len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


def pack(data, password):
    if isinstance(data, str):
        data = data.encode("utf-8")
    salt = os.urandom(SALT_LEN)
    key = derive(password, salt)
    body = keystream_xor(zlib.compress(data, 9), key[:32])
    tag = hmac.new(key[32:], MAGIC + salt + body, hashlib.sha256).digest()
    return MAGIC + salt + tag + body


def unpack(blob, passwords):
    if isinstance(passwords, (str, bytes)):
        passwords = [passwords]
    if len(blob) < HEADER_LEN or blob[: len(MAGIC)] != MAGIC:
        raise VaultError("not a CFV1 vault")
    salt = blob[4:20]
    tag = blob[20:52]
    body = blob[52:]
    signed = MAGIC + salt + body
    for password in passwords:
        if password is None or password == "":
            continue
        key = derive(password, salt)
        expected = hmac.new(key[32:], signed, hashlib.sha256).digest()
        if hmac.compare_digest(tag, expected):
            try:
                return zlib.decompress(keystream_xor(body, key[:32]))
            except zlib.error as exc:
                raise VaultError("vault body corrupt") from exc
    raise VaultError("no key matched")


def is_vault(blob):
    return len(blob) >= HEADER_LEN and blob[: len(MAGIC)] == MAGIC


def _check_member(name):
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
        raise VaultError("unsafe archive member: " + name)
    if len(normalized) > 1 and normalized[1] == ":":
        raise VaultError("absolute archive member: " + name)
    return normalized


def pack_dir(root, password):
    root = os.path.abspath(root)
    buffer = __import__("io").BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for folder, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(folder, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o644 & 0xFFFF) << 16
                with open(full, "rb") as handle:
                    archive.writestr(info, handle.read())
    return pack(buffer.getvalue(), password)


def unpack_dir(blob, password, destination):
    raw = unpack(blob, [password])
    destination = os.path.abspath(destination)
    os.makedirs(destination, exist_ok=True)
    with zipfile.ZipFile(__import__("io").BytesIO(raw)) as archive:
        for member in archive.infolist():
            name = _check_member(member.filename)
            if member.is_dir():
                os.makedirs(os.path.join(destination, name), exist_ok=True)
                continue
            target = os.path.join(destination, name)
            os.makedirs(os.path.dirname(target) or destination, exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(archive.read(member))
    return destination


def keys_from_env(names):
    found = []
    for name in names:
        value = os.environ.get(name)
        if value:
            found.append((name, value))
    return found


def _resolve_keys(key, key_env, prev=False):
    keys = []
    if key:
        keys.append(key)
    if key_env:
        value = os.environ.get(key_env)
        if value:
            keys.append(value)
        if prev:
            previous = os.environ.get(key_env + "_PREV")
            if previous:
                keys.append(previous)
    if not keys:
        raise VaultError("no key supplied; use --key or --key-env")
    return keys


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vault", description="CloudForge CFV1 vault utility")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("pack", "unpack", "pack-dir", "unpack-dir"):
        item = sub.add_parser(name)
        item.add_argument("source")
        item.add_argument("target")
        item.add_argument("--key")
        item.add_argument("--key-env", default="VAULT_KEY")
        item.add_argument("--no-previous", action="store_true")

    info = sub.add_parser("info")
    info.add_argument("source")

    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            with open(args.source, "rb") as handle:
                blob = handle.read()
            print("vault=%s bytes=%d format=%s" % (is_vault(blob), len(blob), "CFV1" if is_vault(blob) else "unknown"))
            return 0

        keys = _resolve_keys(getattr(args, "key", None), getattr(args, "key_env", None), not getattr(args, "no_previous", False))
        primary = keys[0]

        if args.command == "pack":
            with open(args.source, "rb") as handle:
                blob = pack(handle.read(), primary)
            with open(args.target, "wb") as handle:
                handle.write(blob)
        elif args.command == "pack-dir":
            blob = pack_dir(args.source, primary)
            with open(args.target, "wb") as handle:
                handle.write(blob)
        elif args.command == "unpack":
            with open(args.source, "rb") as handle:
                raw = unpack(handle.read(), keys)
            with open(args.target, "wb") as handle:
                handle.write(raw)
        elif args.command == "unpack-dir":
            unpack_dir_path = args.target
            with open(args.source, "rb") as handle:
                blob = handle.read()
            unpack_dir(blob, primary, unpack_dir_path) if len(keys) == 1 else _unpack_any(blob, keys, unpack_dir_path)

        print("%s ok source=%s target=%s" % (args.command, args.source, args.target))
        return 0
    except VaultError as exc:
        print("vault error: %s" % exc, file=sys.stderr)
        return 3


def _unpack_any(blob, keys, destination):
    import io
    raw = None
    last = None
    for key in keys:
        try:
            raw = unpack(blob, [key])
            break
        except VaultError as exc:
            last = exc
    if raw is None:
        raise last or VaultError("no key matched")
    destination = os.path.abspath(destination)
    os.makedirs(destination, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in archive.infolist():
            name = _check_member(member.filename)
            if member.is_dir():
                os.makedirs(os.path.join(destination, name), exist_ok=True)
                continue
            target = os.path.join(destination, name)
            os.makedirs(os.path.dirname(target) or destination, exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(archive.read(member))
    return destination


if __name__ == "__main__":
    raise SystemExit(main())
