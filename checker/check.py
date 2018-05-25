import hashlib
import itertools
import time
from hashlib import sha256
from multiprocessing import Pool

from bip32utils import Base58
from mnemonic import Mnemonic
from two1.bitcoin import crypto


def pk_to_p2wpkh_as_p2sh_addr(pk_hash):
    return Base58.check_encode(b"\x05" + hash160_bytes(bytes.fromhex("0014") + pk_hash))


def hash160_bytes(byte_input):
    return hashlib.new('ripemd160', sha256(byte_input).digest()).digest()


def check(perm):
    s = ' '.join(perm)
    if m.check(s):
        master_key = crypto.HDPrivateKey.master_key_from_mnemonic(s)
        keys = crypto.HDKey.from_path(master_key, "m/49'/0'/0'/0/0")
        address = pk_to_p2wpkh_as_p2sh_addr(keys[-1].public_key._key.ripe_compressed)
        if address == needed_addr:
            return s, address
    return None


words = 'type any words you would like to check here'.split()
needed_addr = '37XTVuaWt1zyUPRgDDpsnoo5ioHk2Da6Fs'

m = Mnemonic('english')

t = time.time()

p = Pool(32)

progress_log = 100000

for i, result in enumerate(p.imap(check, itertools.permutations(words), 32)):
    if result is not None:
        print(result)
    if i % progress_log == 0:
        print("Checked {} permutations. Last {} in {:.2f} sec".format(i, progress_log, time.time() - t))
        t = time.time()
