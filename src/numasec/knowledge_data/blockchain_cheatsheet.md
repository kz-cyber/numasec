# Blockchain & Web3 CTF Cheatsheet

## 🔗 Smart Contract Vulnerabilities

### Reentrancy Attack
```solidity
// Vulnerable pattern
function withdraw() public {
    uint balance = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: balance}("");  // External call BEFORE state update
    balances[msg.sender] = 0;  // State update AFTER
}

// Attack: Create contract that calls withdraw() in receive() function
```

### Integer Overflow/Underflow (pre-Solidity 0.8)
```solidity
// Vulnerable
uint8 balance = 255;
balance += 1;  // Wraps to 0!

uint8 balance = 0;
balance -= 1;  // Wraps to 255!

// Check with SafeMath or Solidity 0.8+
```

### Tx.origin vs Msg.sender
```solidity
// VULNERABLE - uses tx.origin
require(tx.origin == owner);

// SAFE - uses msg.sender
require(msg.sender == owner);

// Attack: Phishing - make owner call your contract which calls vulnerable contract
```

### Unchecked Return Values
```solidity
// VULNERABLE
token.transfer(to, amount);  // Return value ignored!

// SAFE
require(token.transfer(to, amount), "Transfer failed");
```

### Access Control Issues
```solidity
// VULNERABLE - missing modifier
function setOwner(address _owner) public {
    owner = _owner;
}

// SAFE
function setOwner(address _owner) public onlyOwner {
    owner = _owner;
}
```

---

## 🔍 Analysis Tools

### Online Tools
- **Etherscan**: https://etherscan.io - Contract source, transactions
- **Remix IDE**: https://remix.ethereum.org - Deploy & interact
- **Tenderly**: https://tenderly.co - Transaction debugging

### Local Tools
```bash
# Slither - Static analysis
pip install slither-analyzer
slither contract.sol

# Mythril - Symbolic execution
pip install mythril
myth analyze contract.sol

# Echidna - Fuzzing
# https://github.com/crytic/echidna
```

---

## 🔐 Common CTF Patterns

### 1. Find the Private Key
```python
# If you have the mnemonic/seed phrase
from eth_account import Account
Account.enable_unaudited_hdwallet_features()
acct = Account.from_mnemonic("word1 word2 ... word12")
print(acct.address, acct.key.hex())
```

### 2. Analyze Transaction Data
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_KEY'))
tx = w3.eth.get_transaction('0x...')
print(tx)

# Decode input data
from eth_abi import decode
# If you know function signature
```

### 3. Call Contract Functions
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider(RPC_URL))
contract = w3.eth.contract(address=CONTRACT_ADDR, abi=ABI)

# Read
result = contract.functions.getValue().call()

# Write (need private key)
tx = contract.functions.setValue(42).build_transaction({
    'from': MY_ADDR,
    'nonce': w3.eth.get_transaction_count(MY_ADDR),
    'gas': 100000,
})
signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
```

### 4. Brute Force Nonce/Seed
```python
# If weak randomness used
for seed in range(1000000):
    random.seed(seed)
    key = random.randbytes(32)
    # Check if key matches
```

---

## 🎯 CTF Challenge Patterns

### "Unlock the Vault"
1. Find the `password` variable in storage
2. Read storage slot: `w3.eth.get_storage_at(contract, slot)`
3. Private variables are NOT private on blockchain!

### "Claim the Prize"
1. Look for reentrancy
2. Check for weak randomness (block.timestamp, blockhash)
3. Check for integer overflow

### "Become the Owner"
1. Check constructor - was it called?
2. Look for unprotected setter functions
3. Check tx.origin usage

### "Drain the Funds"
1. Reentrancy attack
2. Delegatecall to malicious contract
3. Self-destruct to force send ETH

---

## 💰 Testnet Faucets

- **Sepolia**: https://sepoliafaucet.com/
- **Goerli**: https://goerlifaucet.com/
- **Mumbai (Polygon)**: https://mumbaifaucet.com/

---

## 📚 Quick Reference

### Storage Slots
```python
# Mapping: keccak256(key . slot)
# Dynamic array: keccak256(slot) + index
# String/bytes: slot if < 32 bytes, keccak256(slot) if >= 32

import eth_abi
from web3 import Web3

def get_mapping_slot(key, slot):
    return Web3.keccak(
        eth_abi.encode(['uint256', 'uint256'], [key, slot])
    )
```

### Common ABIs
```json
// ERC20
[
    "function balanceOf(address) view returns (uint256)",
    "function transfer(address to, uint256 amount) returns (bool)",
    "function approve(address spender, uint256 amount) returns (bool)"
]

// Check owner
[
    "function owner() view returns (address)"
]
```

### Useful Opcodes
- `SLOAD(slot)` - Read storage
- `SSTORE(slot, value)` - Write storage
- `DELEGATECALL` - Execute code in caller's context
- `SELFDESTRUCT(recipient)` - Destroy contract, send ETH

---

## 🚨 Flag Format Note

Per SMD CTF 2025:
```
SMDCC{...}
```

Search in:
- Contract source code
- Transaction data
- Event logs
- Storage slots
