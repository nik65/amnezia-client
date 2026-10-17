"""Read-only observer of a disposable GUI account's migration state.

No product APIs are replaced. Private material never leaves this module's
in-memory snapshot; public_summary deliberately returns only hashes and flags.
"""
import configparser
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MANDATORY_CHECKS = ('installed_product_binding', 'real_mapped_gui', 'bootstrap_staged',
                    'natural_disconnect', 'graceful_relaunch', 'native_trial',
                    'nonce_proof', 'profile_cas', 'acknowledged', 'rollback_no_ack',
                    'rollback_profile_preserved', 'cleanup')


class ObservationError(RuntimeError):
    pass


def private_read(path, uid, limit=65536):
    path = Path(path)
    # Check every existing ancestor, including symlinks in parent components.
    for parent in [path.parent, *path.parents][:-1]:
        item = parent.lstat()
        if not stat.S_ISDIR(item.st_mode) or item.st_mode & 0o022:
            raise ObservationError('unsafe private ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        item = os.fstat(fd)
        if (not stat.S_ISREG(item.st_mode) or item.st_uid != uid
                or item.st_mode & 0o077 or not 0 <= item.st_size <= limit):
            raise ObservationError('unsafe private file')
        value = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if len(value) != item.st_size or (item.st_size, item.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ObservationError('private file changed during read')
        return value
    finally:
        os.close(fd)


def qt_bytearray(value):
    """Decode QSettings' escaped QByteArray; reject unsupported/ambiguous input."""
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value.startswith('@ByteArray(') or not value.endswith(')'):
        raise ObservationError('settings are not a QByteArray')
    text = value[11:-1]
    result = bytearray()
    escapes = {'n': 10, 'r': 13, 't': 9, 'b': 8, 'f': 12, 'v': 11,
               'a': 7, '\\': 92, '"': 34, "'": 39, '?': 63, '0': 0}
    index = 0
    while index < len(text):
        char = text[index]
        index += 1
        if char != '\\':
            if ord(char) > 127:
                raise ObservationError('non-ASCII fixture settings')
            result.append(ord(char))
            continue
        if index == len(text):
            raise ObservationError('truncated settings escape')
        char = text[index]
        index += 1
        if char == 'x':
            match = re.match(r'[0-9a-fA-F]{1,2}', text[index:])
            if not match:
                raise ObservationError('invalid hexadecimal escape')
            result.append(int(match[0], 16))
            index += len(match[0])
        elif char in escapes:
            result.append(escapes[char])
        else:
            raise ObservationError('unsupported settings escape')
    return bytes(result)


def decrypt(envelope, key):
    """Same AMG1/nonce12/ciphertext/tag16 AES-256-GCM as secret store."""
    if len(key) != 32 or len(envelope) < 32 or envelope[:4] != b'AMG1':
        raise ObservationError('invalid private envelope')
    name = ctypes.util.find_library('crypto')
    if not name:
        raise ObservationError('OpenSSL unavailable')
    lib = ctypes.CDLL(name)
    ptr = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_new.restype = ptr
    lib.EVP_aes_256_gcm.restype = ptr
    lib.EVP_CIPHER_CTX_free.argtypes = [ptr]
    lib.EVP_DecryptInit_ex.argtypes = [ptr, ptr, ptr, ptr, ptr]
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [ptr, ctypes.c_int, ctypes.c_int, ptr]
    lib.EVP_DecryptUpdate.argtypes = [ptr, ptr, ptr, ptr, ctypes.c_int]
    lib.EVP_DecryptFinal_ex.argtypes = [ptr, ptr, ptr]
    context = lib.EVP_CIPHER_CTX_new()
    if not context:
        raise ObservationError('OpenSSL context unavailable')
    body = envelope[16:-16]
    output = ctypes.create_string_buffer(len(body) + 16)
    count, tail = ctypes.c_int(), ctypes.c_int()
    try:
        ok = lib.EVP_DecryptInit_ex(context, lib.EVP_aes_256_gcm(), None, key, envelope[4:16]) == 1
        ok = ok and lib.EVP_CIPHER_CTX_ctrl(context, 0x11, 16, envelope[-16:]) == 1
        ok = ok and lib.EVP_DecryptUpdate(context, output, ctypes.byref(count), body, len(body)) == 1
        ok = ok and lib.EVP_DecryptFinal_ex(context, ctypes.byref(output, count.value), ctypes.byref(tail)) == 1
        if not ok:
            raise ObservationError('private envelope authentication failed')
        return output.raw[:count.value + tail.value]
    finally:
        lib.EVP_CIPHER_CTX_free(context)


def canonical_hash(value):
    # Fixture uses ASCII strings and integer JSON fields only, matching Qt's
    # sorted object keys and compact representation. Reject floats/non-ASCII.
    def validate(item):
        if isinstance(item, float):
            raise ObservationError('non-fixture JSON number')
        if isinstance(item, str) and not item.isascii():
            raise ObservationError('non-fixture JSON text')
        if isinstance(item, dict):
            for key, child in item.items():
                validate(key)
                validate(child)
        if isinstance(item, list):
            for child in item:
                validate(child)
    validate(value)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def account_tree(path, home, uid):
    path, home = Path(path), Path(home)
    try:
        relative = path.relative_to(home)
    except ValueError:
        raise ObservationError('private store outside account home') from None
    current = home
    for part in ('', *relative.parts):
        if part:
            current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise ObservationError('unsafe account directory')


def snapshot(settings, secret_directory, uid, home=None):
    if home is not None:
        account_tree(Path(settings).parent, home, uid)
        account_tree(secret_directory, home, uid)
        if Path(secret_directory).lstat().st_mode & 0o077:
            raise ObservationError('migration store is not private')
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(private_read(settings, uid).decode('utf-8'))
    profiles = json.loads(qt_bytearray(parser['Servers']['serversList']))
    if not isinstance(profiles, list) or len(profiles) != 1:
        raise ObservationError('isolated profile count differs')
    profile = profiles[0]
    server_id = profile.get('storageServerId')
    if not isinstance(server_id, str) or not server_id:
        raise ObservationError('stable profile ID missing')
    directory = Path(secret_directory)
    key = private_read(directory / 'key', uid)
    path = directory / hashlib.sha256(server_id.encode()).hexdigest()
    journal = json.loads(decrypt(private_read(path, uid), key))
    if not isinstance(journal, dict):
        raise ObservationError('invalid journal object')
    return {'profile': profile, 'journal': journal, 'profile_sha256': canonical_hash(profile)}


def public_summary(observation):
    journal = observation['journal']
    return {'profile_sha256': observation['profile_sha256'],
            'state': journal.get('state'),
            'source_matches': journal.get('sourceHash') == observation['profile_sha256'],
            'candidate_matches': journal.get('candidateHash') == observation['profile_sha256'],
            'challenge_present': bool(journal.get('challengeReceipt'))}
