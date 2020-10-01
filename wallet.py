import base58
import codecs
import hashlib

from ecdsa import NIST256p
from ecdsa import SigningKey

import utils


class Wallet(object):

    def __init__(self):
        self._private_key = SigningKey.generate(curve=NIST256p)
        self._public_key = self._private_key.get_verifying_key()
        self._blockchain_address = self.generate_blockchain_address()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()

    @property
    def public_key(self):
        return self._public_key.to_string().hex()

    @property
    def blockchain_address(self):
        return self._blockchain_address

    # 公開鍵と秘密鍵の生成をブロックチェーンアドレスとして一つにまとめたい理由から作られている関数
    def generate_blockchain_address(self):
        public_key_bytes = self._public_key.to_string()
        sha256_bpk = hashlib.sha256(public_key_bytes)
        # bpkはbはbyteでここではおそらくbyte型にするという意味で使われている
        sha256_bpk_digest = sha256_bpk.digest()

        ripemed160_bpk = hashlib.new('ripemd160')
        ripemed160_bpk.update(sha256_bpk_digest)
        ripemed160_bpk_digest = ripemed160_bpk.digest()
        # digestとしてやるとhashが取得できるらしい
        ripemed160_bpk_hex = codecs.encode(ripemed160_bpk_digest, 'hex')
        # ここではhashをhexとしてやっている

        network_byte = b'00'
        # b'00'はバイナリデータを00として足しているらしい？/バイナリデータとは、テキスト(可読)形式以外のデータ全般です。
        # 一般に人間がバイナリデータを直接読み書きすることは少なく、コンピュータ(プログラム)が主に取り扱う。
        network_bitcoin_public_key = network_byte + ripemed160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')

        sha256_bpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        # この2行でsha256を用いてhashを作っている
        sha256_2_nbpk = hashlib.sha256(sha256_bpk_digest)
        # 上1行でhash化を2回している
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        # ここでdigestにしている
        sha256_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        # そしてここでhexにしている

        checksum = sha256_hex[:8]
        # 前から8個checksumとして使う

        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')

        blockchain_address = base58.b58encode(address_hex).decode('utf-8')
        return blockchain_address


class Transaction(object):

    def __init__(self, sender_private_key, sender_public_key,
                 sender_blockchain_address, recipient_blockchain_address,
                 value):
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_public_key
        self.sender_blockchain_address = sender_blockchain_address
        self.recipient_blockchain_address = recipient_blockchain_address
        self.value = value

    def generate_signature(self):
        sha256 = hashlib.sha256()
        # これはオブジェクト
        transaction = utils.sorted_dict_by_key({
            'sender_blockchain_address': self.sender_blockchain_address,
            'recipient_blockchain_address': self.recipient_blockchain_address,
            'value': float(self.value)
        })
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        private_key = SigningKey.from_string(
            bytes().fromhex(self.sender_private_key), curve=NIST256p)
        private_key_sign = private_key.sign(message)
        signature = private_key_sign.hex()
        return signature


if __name__ == '__main__':
    wallet_M = Wallet()
    # Mはマイニング
    wallet_A = Wallet()
    wallet_B = Wallet()
    t = Transaction(
        wallet_A.private_key, wallet_A.public_key, wallet_A.blockchain_address,
        wallet_B.blockchain_address, 1.0)

    ################ Blockchain Node

    import blockchain
    block_chain = blockchain.BlockChain(
        blockchain_address=wallet_M.blockchain_address)
    is_added = block_chain.add_transaction(
        wallet_A.blockchain_address,
        wallet_B.blockchain_address,
        1.0,
        # 上3つがトランザクションの内容で、下2つは必要なパブリックキーとシグネチャー
        wallet_A.public_key,
        t.generate_signature())
    print('Added?', is_added)
    # 加えられたかを確認するためのプリント
    block_chain.mining()
    # ここでマイニングを実行してやるとブロックチェーンが生成される
    utils.pprint(block_chain.chain)
    # ここで中身をみているらしい

    print('A', block_chain.calculate_total_amount(wallet_A.blockchain_address))
    print('B', block_chain.calculate_total_amount(wallet_B.blockchain_address))
#     AさんとBさんの合計金額を確認

