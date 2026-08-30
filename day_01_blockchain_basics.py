# ============================================================
# DAY 01: BLOCKCHAIN BASICS
# ============================================================

print("DAY 01 - BLOCKCHAIN BASICS")


# ============================================================
# 1. WHAT IS BLOCKCHAIN?
# ============================================================

print("\n1. WHAT IS BLOCKCHAIN?")

print("A blockchain is a distributed digital ledger")
print("that records data in a sequence of connected blocks.")


# ============================================================
# 2. WHAT IS A BLOCK?
# ============================================================

print("\n2. WHAT IS A BLOCK?")

block = {
    "index": 1,
    "data": "Alice sends 10 coins to Bob",
    "previous_hash": "0000"
}

print("Block Index:", block["index"])
print("Block Data:", block["data"])
print("Previous Hash:", block["previous_hash"])


# ============================================================
# 3. BLOCKCHAIN DATA
# ============================================================

print("\n3. BLOCKCHAIN DATA")

transactions = [
    "Alice sends 10 coins to Bob",
    "Bob sends 5 coins to Charlie",
    "Charlie sends 2 coins to David"
]

for transaction in transactions:
    print("-", transaction)


# ============================================================
# 4. HASH
# ============================================================

print("\n4. HASH")

data = "Alice sends 10 coins to Bob"

hash_value = hash(data)

print("Data:", data)
print("Hash:", hash_value)

print("\nA hash is a value generated from data.")
print("Changing the input produces a different hash value.")


# ============================================================
# 5. SIMPLE BLOCK
# ============================================================

print("\n5. SIMPLE BLOCK")


def create_block(index, data, previous_hash):
    block = {
        "index": index,
        "data": data,
        "previous_hash": previous_hash
    }

    block["hash"] = hash(
        str(block["index"]) +
        block["data"] +
        str(block["previous_hash"])
    )

    return block


block_1 = create_block(
    1,
    "Alice sends 10 coins to Bob",
    "0000"
)

print(block_1)


# ============================================================
# 6. CONNECTING BLOCKS
# ============================================================

print("\n6. CONNECTING BLOCKS")

block_2 = create_block(
    2,
    "Bob sends 5 coins to Charlie",
    block_1["hash"]
)

block_3 = create_block(
    3,
    "Charlie sends 2 coins to David",
    block_2["hash"]
)

print("Block 1:", block_1)
print("Block 2:", block_2)
print("Block 3:", block_3)


# ============================================================
# 7. BLOCKCHAIN
# ============================================================

print("\n7. BLOCKCHAIN")

blockchain = [
    block_1,
    block_2,
    block_3
]

for block in blockchain:
    print(
        "Block:",
        block["index"],
        "| Data:",
        block["data"],
        "| Previous Hash:",
        block["previous_hash"]
    )


# ============================================================
# 8. CHAIN STRUCTURE
# ============================================================

print("\n8. CHAIN STRUCTURE")

print("""
Block 1
   ↓
Block 2
   ↓
Block 3
   ↓
Block 4
""")

print("Each block stores information about the")
print("previous block, creating a chain.")


# ============================================================
# 9. BASIC BLOCKCHAIN VALIDATION
# ============================================================

print("\n9. BASIC BLOCKCHAIN VALIDATION")


def validate_blockchain(chain):

    for i in range(1, len(chain)):

        current_block = chain[i]
        previous_block = chain[i - 1]

        if current_block["previous_hash"] != previous_block["hash"]:
            return False

    return True


print("Blockchain valid:", validate_blockchain(blockchain))


# ============================================================
# 10. TAMPERING WITH DATA
# ============================================================

print("\n10. DATA TAMPERING")

blockchain[1]["data"] = "Bob sends 5000 coins to Charlie"

print("Block 2 was modified.")

print(
    "Blockchain valid after modification:",
    validate_blockchain(blockchain)
)

print("\nChanging blockchain data can break the relationship")
print("between blocks and make the chain invalid.")


# ============================================================
# 11. BASIC BLOCKCHAIN CONCEPTS
# ============================================================

print("\n11. BASIC BLOCKCHAIN CONCEPTS")

concepts = [
    "Block",
    "Transaction",
    "Hash",
    "Previous Hash",
    "Blockchain",
    "Distributed Ledger",
    "Consensus",
    "Cryptography"
]

for concept in concepts:
    print("-", concept)


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("DAY 01 COMPLETED")
print("=" * 60)

print("""
Today you learned:

1. What Blockchain is
2. Blocks
3. Transactions
4. Hashes
5. Previous Hashes
6. Creating a simple block
7. Connecting blocks
8. Blockchain structure
9. Basic blockchain validation
10. Data tampering
11. Core blockchain concepts
""")
