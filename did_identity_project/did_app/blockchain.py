"""
Blockchain simulation module for storing credential hashes
"""
import hashlib
import json
import time
import random

class BlockchainSimulator:
    """
    Simple blockchain simulator for storing credential hashes
    """
    def __init__(self):
        # Initialize the blockchain with a genesis block
        self.chain = [{
            'index': 0,
            'timestamp': time.time(),
            'transactions': [],
            'previous_hash': '0',
            'nonce': 0,
            'hash': '000000000000000000000000000000000000000000000000000000000000000'
        }]
        self.current_transactions = []
        self.nodes = set()
        self.last_block_number = 0
    
    def new_block(self, nonce, previous_hash=None):
        """
        Create a new block in the blockchain
        """
        self.last_block_number += 1
        block = {
            'index': len(self.chain),
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'nonce': nonce,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        
        # Calculate the hash of this block
        block['hash'] = self.hash(block)
        
        # Reset the current list of transactions
        self.current_transactions = []
        
        # Add the block to the chain
        self.chain.append(block)
        
        return block
    
    def new_transaction(self, credential_id, signature):
        """
        Create a new transaction to go into the next mined block
        """
        # Create transaction data
        transaction = {
            'credential_id': credential_id,
            'signature': signature,
            'timestamp': time.time()
        }
        
        # Calculate transaction hash
        tx_string = json.dumps(transaction, sort_keys=True).encode()
        tx_hash = hashlib.sha256(tx_string).hexdigest()
        transaction['tx_hash'] = tx_hash
        
        # Add to pending transactions
        self.current_transactions.append(transaction)
        
        # Mine a new block (simple simulation)
        nonce = self._proof_of_work_simulation()
        block = self.new_block(nonce)
        
        return tx_hash, block['index']
    
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def _proof_of_work_simulation(self):
        """
        Simple proof of work simulation
        """
        # Simulate some computational work
        return random.randint(1, 100000)
    
    def verify_transaction(self, tx_hash):
        """
        Verify that a transaction exists in the blockchain
        """
        # Search for the transaction in all blocks
        for block in self.chain:
            for tx in block['transactions']:
                if tx.get('tx_hash') == tx_hash:
                    return True, block['index'], block['timestamp']
        
        return False, None, None

# Create a singleton instance
blockchain = BlockchainSimulator()

def simulate_blockchain_transaction(credential_id, signature):
    """
    Add a credential hash to the blockchain simulator
    """
    # Add transaction to blockchain and get transaction hash
    tx_hash, block_number = blockchain.new_transaction(credential_id, signature)
    
    return tx_hash, block_number

def verify_blockchain_transaction(tx_hash):
    """
    Verify that a transaction exists in the blockchain
    """
    exists, block_number, timestamp = blockchain.verify_transaction(tx_hash)
    
    if exists:
        return {
            'verified': True,
            'block_number': block_number,
            'timestamp': timestamp
        }
    else:
        return {
            'verified': False
        }
