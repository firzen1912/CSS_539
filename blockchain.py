import time
import binascii
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from Crypto.Hash import SHA256


class Wallet:
    def __init__(self):
        self.sk = SigningKey.generate(curve=SECP256k1)
        self.vk = self.sk.verifying_key
        self.private_key = self.sk.to_string().hex()
        self.public_key = self.vk.to_string().hex()

    def sign(self, message):
        digest = SHA256.new(message.encode()).digest()
        return self.sk.sign(digest).hex()

    def verify(self, message, signature):
        digest = SHA256.new(message.encode()).digest()
        try:
            return self.vk.verify(bytes.fromhex(signature), digest)
        except:
            return False


class Transaction:
    def __init__(self, sender, recipient, tx_id):
        self.sender = sender
        self.recipient = recipient
        self.tx_id = tx_id
        self.signature = sender.sign(str(tx_id))

    def verify(self):
        return self.sender.verify(str(self.tx_id), self.signature)


class Block:
    def __init__(self, index, transactions, previous_hash, difficulty):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.difficulty = difficulty
        self.nonce, self.hash = self.mine()

    def compute_hash(self, nonce):
        tx_data = "".join([str(tx.tx_id) + tx.signature for tx in self.transactions])
        block_data = str(self.index) + self.previous_hash + tx_data + str(nonce)
        return SHA256.new(block_data.encode()).hexdigest()

    def mine(self):
        prefix = '0' * self.difficulty
        for nonce in range(10**10):
            hash_result = self.compute_hash(nonce)
            if hash_result.startswith(prefix):
                return nonce, hash_result
        return None, None

    def verify(self):
        expected_hash = self.compute_hash(self.nonce)
        return expected_hash == self.hash and self.hash.startswith('0' * self.difficulty)


class Blockchain:
    def __init__(self, difficulty):
        self.chain = []
        self.difficulty = difficulty
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, [], "0", self.difficulty)
        self.chain.append(genesis)

    def add_block(self, transactions):
        prev_hash = self.chain[-1].hash
        index = len(self.chain)
        block = Block(index, transactions, prev_hash, self.difficulty)
        self.chain.append(block)

    def verify_chain(self):
        for i, block in enumerate(self.chain):
            if not block.verify():
                return False
            if i > 0 and block.previous_hash != self.chain[i - 1].hash:
                return False
        return True


def simulate_blockchain(difficulty):
    alice = Wallet()
    bob = Wallet()
    blockchain = Blockchain(difficulty)
    tx_count = 0
    batch = []

    start = time.time()
    for i in range(1, 101):
        sender = alice if i % 2 == 0 else bob
        recipient = bob if i % 2 == 0 else alice
        tx = Transaction(sender, recipient, tx_id=i)
        batch.append(tx)
        if len(batch) == 10:
            blockchain.add_block(batch)
            batch = []
    end = time.time()

    valid = blockchain.verify_chain()

    print(f"Difficulty: {difficulty} (leading zeros)")
    print(f"Valid Chain: {valid}")
    print(f"Verification Time: {end - start} seconds")
    print("-" * 40)


if __name__ == "__main__":
    for difficulty in [1,2,3,4,5,6]:
        simulate_blockchain(difficulty)
