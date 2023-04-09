from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import NoReturn
from snekhide import console
from pathlib import Path
import hashlib
import base64
import typer
import os
import secrets
import zstandard

# Array to retrieve the corresponding base64 character for a 6-bit int (0-63)
B64_CHAR = r"""ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"""
# Dictionary to retrieve the corresponding 6-bit int for a base64 character
B64_DICT = dict((char, index) for index, char in enumerate(B64_CHAR))
# Single hash iteration password used with the --disable-encryption option
# Must NEVER be changed to not break compatibility with future versions
NO_ENCRYPTION_PASSWORD = "pa漢字word☕💩💩💩"


# Type new password + confirmation prompt; repeated until the inputs match
def new_password_prompt() -> str:
    while True:
        password = typer.prompt("Set data password", hide_input=True)
        confirm = typer.prompt("Repeat data password", hide_input=True)
        if password != confirm:
            console.error("The confirmation prompt does not match, try again...")
        else:
            return confirm


# Prints error and aborts if predicted and actual sizes don't match (should never happen)
def validate_predicted_size(predicted: int, actual: int):
    if predicted != actual:
        console.abort("Output size incorrectly predicted; this should never happen, please report this bug")


# Embed a file or message into an image
def embed(source: Path, data: bytes, noise: bool, target=None, extensions: list[str] = None, is_plaintext: bool = False,
          binary_plaintext: bool = False, hash_strength: int = 6, compression_level: int = 14,
          write_stdout: bool = False, password: str = None) -> int:
    if target is None:
        target = source.with_suffix('.snek' + source.suffix)

    salt_b64 = base64.b64encode(os.urandom(6)).decode()
    salt = base64.b64decode(salt_b64 + ('=' * (len(salt_b64) % 4)))

    extensions = [] if extensions is None else extensions
    extension = extensions[-2] + extensions[-1] if len(extensions) > 1 and extensions[-1] == '.gz' else \
        extensions[-1] if len(extensions) > 0 else None
    extension_xor = None if (extension is None) else bytes((a ^ 12) ^ b for (a, b) in zip(extension.encode('utf-8'), salt[::-1]))

    extension_length = 0 if (extension is None) else len(extension_xor)
    if extension_length > 255:
        console.abort("""The file extension for the data file is too long:
            change the extension or use the --disable-file-info option""")

    im: Image = None
    try:
        im = Image.open(source)
    except:
        error_img_read()

    if compression_level > 0:
        if not is_plaintext or binary_plaintext:
            console.out("Compressing data...")
        compressed_data = zstandard.ZstdCompressor(compression_params=zstandard.ZstdCompressionParameters(
            compression_level=compression_level,
            strategy=9
        )).compress(data)
        if len(data) < len(compressed_data):
            if not is_plaintext or binary_plaintext:
                console.warn("Data cannot be compressed further, disabling compression...")
            compression_level = 0
            del compressed_data
        else:
            data = compressed_data
    data = extension_xor + data

    nonce = secrets.token_bytes(12)  # GCM mode needs a 12 bytes nonce
    # Predicting size of the AES-GCM output encoded in Base64
    # The GCM tag size is always 16
    len_payload = ((len(data) + len(nonce) + 16) * 4 / 3).__ceil__()

    flags = (secrets.randbits(5) << 1) | binary_plaintext
    data_info = (hash_strength << 4) | ((compression_level > 0) << 3) | (is_plaintext << 2)
    data_header = bytes([data_info, extension_length, flags])
    data_header_xor = bytes((a ^ 24) ^ b for (a, b) in zip(data_header, salt[::-1]))
    data_header_b64 = base64.b64encode(data_header_xor).decode()

    data_len_bytes = len_payload.to_bytes(6, 'big', signed=False)
    data_len_xor = bytes((a ^ 64) ^ b for (a, b) in zip(data_len_bytes, salt[::-1]))
    data_len_b64 = base64.b64encode(data_len_xor).decode()

    len_data_pixels = (len_payload + len(salt_b64) + len(data_header_b64) + len(data_len_b64)) * 2
    width, height = im.size
    len_img_pixels = width * height
    if len_data_pixels > len_img_pixels:
        console.error("Data too big, cannot write to chosen file; use stronger compression or bigger image:")
        console.abort("{} total pixels required; {} more pixels required"
                      .format(len_data_pixels, len_data_pixels - len_img_pixels))

    if password is None:
        password = NO_ENCRYPTION_PASSWORD if hash_strength == 0 else new_password_prompt()
    if hash_strength != 0:
        console.out("Generating hash with strength {}...".format(hash_strength))
    key = hashlib.pbkdf2_hmac('sha512', bytes(password, 'raw_unicode_escape'), salt, 10 ** hash_strength, dklen=32)

    console.out("Obfuscating data..." if hash_strength == 0 else "Encrypting data...")
    encrypted = nonce + AESGCM(key).encrypt(nonce, data, b'')
    encrypted_b64 = base64.b64encode(encrypted).decode().rstrip('=')

    console.out("Writing data...")
    validate_predicted_size(len_payload, len(encrypted_b64))
    data = '{}{}{}{}'.format(salt_b64, data_header_b64, data_len_b64, encrypted_b64)
    validate_predicted_size(len_data_pixels, len(data) * 2)
    pix_colors = im.load()
    bit_stream = Base64BitStream(data)

    no_noise_written: bool = True
    for h in range(height):
        for w in range(width):
            loc = h * width + w
            if loc < len_data_pixels:
                hR, hG, hB = next(bit_stream)
                R, G, B = pix_colors[w, h]
                pix_colors[w, h] = R - R % 2 + hR, G - G % 2 + hG, B - B % 2 + hB
            elif noise:
                if no_noise_written:
                    console.out("Writing noise...")
                    no_noise_written = False
                hR, hG, hB = calc_noise()
                R, G, B = pix_colors[w, h]
                pix_colors[w, h] = R - R % 2 + hR, G - G % 2 + hG, B - B % 2 + hB
            else:
                break
    if write_stdout:
        console.stream(im.tobytes())
    else:
        console.success("Data successfully written to file:")
        console.out(target.absolute())
        im.save(target, 'PNG')
    im.close()
    return len_data_pixels


# Calculate three bits of random noise; used for remaining pixels in the image
def calc_noise():
    bits = secrets.randbelow(8)
    return bits & 0b000001, (bits & 0b000010) >> 1, (bits & 0b000100) >> 2


# Stream yielding the next three bits of data on each subsequent read
class Base64BitStream:
    def __init__(self, text): self.generator = self.__calc_text_stream__(text)
    def __next__(self): return next(self.generator)
    def __iter__(self): return self

    @staticmethod
    def __calc_text_stream__(text: str):
        for char in text:
            b64_val = B64_DICT[char]
            yield (b64_val & 0b00100000) >> 5, (b64_val & 0b00010000) >> 4, (b64_val & 0b00001000) >> 3
            yield (b64_val & 0b00000100) >> 2, (b64_val & 0b00000010) >> 1, b64_val & 0b00000001


# Image read error
def error_img_read() -> NoReturn:
    console.abort("Error: The source file is not an image")


# Unidentified file error
def error_read_nodata() -> NoReturn:
    console.abort("Error: No hidden data contained in file")


# Failure reading encrypted data
def error_read_fail() -> NoReturn:
    console.abort("Wrong password or no hidden data contained in file")


# Read file or message from image
def read(image: Path, write_stdout: bool = False, password: str = None) -> None:
    try:
        im = Image.open(image)
    except:
        error_img_read()

    width, height = im.size
    pix_colors = im.load()
    hiddens = []
    for h in range(height):
        for w in range(width):
            R, G, B = pix_colors[w, h]
            hiddens.append((R % 2, G % 2, B % 2))
    hidden_data = [B64_CHAR[int(''.join(map(str, hiddens[i] + hiddens[i + 1])), 2)] for i in range(0, len(hiddens), 2)]

    salt_b64 = ''.join(hidden_data[0:8])
    salt = base64.b64decode(salt_b64 + ('=' * (len(salt_b64) % 4)))

    data_header_xor = base64.b64decode(''.join(hidden_data[8:12]).encode())
    # Third byte of header is reserved
    data_header_bytes = bytes((a ^ 24) ^ b for (a, b) in zip(data_header_xor, salt[::-1]))
    data_info = data_header_bytes[0]

    hash_strength = data_info >> 4
    is_compressed = bool(data_info & 0b00001000)
    is_plaintext = bool(data_info & 0b00000100)
    extension_len = data_header_bytes[1]
    has_extension = extension_len > 0
    flags = data_header_bytes[2]
    binary_plaintext = bool(flags & 0b00000001)
    if hash_strength > 9:
        error_read_nodata()
    if write_stdout and password is None and hash_strength != 0:
        console.abort("Writing to stdout requires the password to be passed with the -p option")

    pos_data_len = 12
    pos_file_start = pos_data_len + 8

    data_len_xor = base64.b64decode(''.join(hidden_data[pos_data_len:pos_file_start]).encode())
    data_len_bytes = bytes((a ^ 64) ^ b for (a, b) in zip(data_len_xor, salt[::-1]))
    data_len = int.from_bytes(data_len_bytes, 'big', signed=False)

    if (pos_file_start + data_len) > ((width * height) / 2).__ceil__():
        error_read_nodata()

    data_b64 = (''.join(hidden_data[pos_file_start:pos_file_start + data_len]) + '=' * (data_len % 4)).encode()
    data = base64.b64decode(data_b64)

    if write_stdout and password is None and hash_strength != 0:
        console.abort("Writing to stdout requires the password to be passed with the -p option")
    # Ignoring password received with the -p option if the file was written as unencrypted
    if password is None or hash_strength == 0:
        password = NO_ENCRYPTION_PASSWORD if hash_strength == 0 else typer.prompt("Type unlock password", hide_input=True)
    if hash_strength != 0:
        console.out("Generating password hash...".format(hash_strength))
    key = hashlib.pbkdf2_hmac('sha512', bytes(password, 'raw_unicode_escape'), salt, 10 ** hash_strength, dklen=32)

    console.out("Deobfuscating data..." if hash_strength == 0 else "Decrypting data...")
    decrypted: bytes
    try:
        decrypted = AESGCM(key).decrypt(data[:12], data[12:], b'')
    except:
        error_read_nodata() if hash_strength == 0 else error_read_fail()

    file_extension_xor = decrypted[:extension_len] if has_extension else None
    file_extension_bytes = bytes((a ^ 12) ^ b for (a, b) in zip(file_extension_xor, salt[::-1])) if has_extension else None
    file_extension: str = ''
    try:
        file_extension = file_extension_bytes.decode('utf-8') if has_extension else ''
    except:
        error_read_nodata()

    console.out("Decompressing data...")
    decrypted = zstandard.decompress(decrypted[extension_len:]) if is_compressed else decrypted[extension_len:]

    if is_plaintext or write_stdout:
        console.success("Hidden message successifully retrieved:")
        if binary_plaintext or write_stdout:
            console.stream(decrypted)
        else:
            console.out(decrypted.decode('utf-8'))
    else:
        out_file = image.with_suffix('.snek'+file_extension)
        out_file.write_bytes(decrypted)
        console.success("""Data successifully saved to file:""")
        console.out(out_file.absolute())
