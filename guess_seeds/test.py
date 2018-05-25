from electrum import util, keystore, bitcoin
import argparse
import sys
import threading

MAX_THREADS=25
TARGET_ADDR="3CcxyPhyvyc3S9UuPfu42GNZLvVVV11Uk8"
# How many of the address indexes to try. Default to just /0.
# i.e. last digit in derivation path: m/49'/0'/0'/0/0
MAX_ADDR_IDX=1

def deriveAddresses(line, xprv, i):
    xprv2, _xpub = bitcoin.bip32_private_derivation(xprv, "", str(i))
    btc_addr = xpub2btc(_xpub)
    if (TARGET_ADDR.lower() == btc_addr.lower()):
        privkey = xprv2btc(xprv2)
        print("FOUND: " + privkey)
        g = open("found.txt", "w")
        g.write(line + "\n")
        g.write(privkey + "\n")
        g.close()
        exit(1)
    sys.stdout.write(btc_addr + "\r")
    sys.stdout.flush()

def checkPassphrase(line):
    passw = ""

    seed = util.bh2u(keystore.bip39_to_seed(line, passw))
    seed = util.bfh(seed)
    xprv, _xpub = bitcoin.bip32_root(seed, "standard")
    xprv, _xpub = bitcoin.bip32_private_derivation(xprv, "", "49'")
    xprv, _xpub = bitcoin.bip32_private_derivation(xprv, "", "0'")
    xprv, _xpub = bitcoin.bip32_private_derivation(xprv, "", "0'")
    xprv, _xpub = bitcoin.bip32_private_derivation(xprv, "", "0")
    for i in range(MAX_ADDR_IDX):
        deriveAddresses(line, xprv, i)

def xpub2btc(xpub):
    _xtype, _depth, _fp, _cn, _c, K = bitcoin.deserialize_xpub(xpub)
    return bitcoin.pubkey_to_address("p2wpkh-p2sh", util.bh2u(K))

def xprv2btc(xprv):
    _xtype, _depth, _fp, _cn, _c, k = bitcoin.deserialize_xprv(xprv)
    privkey = bitcoin.serialize_privkey(k, True, "p2wpkh-p2sh")
    return privkey

def main():
    f = open('seedwords.txt')
    lines = f.read().split('\n')

    threads = []

    for line in lines:
        (checksum_ok, wordlist_ok) = keystore.bip39_is_checksum_valid(line)
        print("[CHECK] " + line)
        if not wordlist_ok:
            print("       Unknown words!", file=sys.stderr)
            continue
        if not checksum_ok:
            print("       Checksum NOT OK!", file=sys.stderr)
            continue
        print("       Check passed. Queued.")
        t = threading.Thread(target=checkPassphrase, args=(line,))
        threads.append(t)
        t.start()

        if len(threads) == MAX_THREADS:
            for t in threads:
                t.join()

            threads.clear()

if __name__ == "__main__":
    main()