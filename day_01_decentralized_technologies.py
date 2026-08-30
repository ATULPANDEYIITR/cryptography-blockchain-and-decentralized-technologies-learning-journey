# ============================================================
# DAY 01: DECENTRALIZED TECHNOLOGIES
# ============================================================

print("DAY 01 - DECENTRALIZED TECHNOLOGIES")


# ============================================================
# 1. WHAT IS DECENTRALIZATION?
# ============================================================

print("\n1. WHAT IS DECENTRALIZATION?")

print("Decentralization is an approach where control,")
print("decision-making, or data is distributed across")
print("multiple participants instead of being controlled")
print("by a single central authority.")


# ============================================================
# 2. CENTRALIZED SYSTEM
# ============================================================

print("\n2. CENTRALIZED SYSTEM")

centralized_system = {
    "Central Server": "Controls the system",
    "Users": "Connect to the central server",
    "Decision Making": "Centralized"
}

for component, role in centralized_system.items():
    print(component, "->", role)


# ============================================================
# 3. DECENTRALIZED SYSTEM
# ============================================================

print("\n3. DECENTRALIZED SYSTEM")

decentralized_system = {
    "Node 1": "Participant",
    "Node 2": "Participant",
    "Node 3": "Participant",
    "Node 4": "Participant"
}

for node, role in decentralized_system.items():
    print(node, "->", role)


# ============================================================
# 4. CENTRALIZED VS DECENTRALIZED
# ============================================================

print("\n4. CENTRALIZED VS DECENTRALIZED")

print("""
CENTRALIZED:

       Central Server
        /    |    \\
       /     |     \\
   User    User    User


DECENTRALIZED:

   Node ------ Node
    |  \\      /  |
    |   \\    /   |
   Node ------ Node
""")

print("Centralized systems depend heavily on a central point.")
print("Decentralized systems distribute participation across nodes.")


# ============================================================
# 5. WHAT IS A NODE?
# ============================================================

print("\n5. WHAT IS A NODE?")

node = {
    "id": 1,
    "status": "Online",
    "role": "Network Participant"
}

print("Node ID:", node["id"])
print("Status:", node["status"])
print("Role:", node["role"])

print("\nA node is a device or system participating")
print("in a distributed network.")


# ============================================================
# 6. PEER-TO-PEER NETWORK
# ============================================================

print("\n6. PEER-TO-PEER NETWORK")

peers = [
    "Node A",
    "Node B",
    "Node C",
    "Node D"
]

print("Network Peers:")

for peer in peers:
    print("-", peer)

print("\nIn a Peer-to-Peer (P2P) network,")
print("participants can communicate directly with one another.")


# ============================================================
# 7. DISTRIBUTED DATA
# ============================================================

print("\n7. DISTRIBUTED DATA")

network = {
    "Node A": "Data Copy",
    "Node B": "Data Copy",
    "Node C": "Data Copy"
}

for node, data in network.items():
    print(node, "->", data)

print("\nDistributed systems can maintain information")
print("across multiple participating nodes.")


# ============================================================
# 8. NODE COMMUNICATION
# ============================================================

print("\n8. NODE COMMUNICATION")


def send_message(sender, receiver, message):
    print(sender, "->", receiver, ":", message)


send_message(
    "Node A",
    "Node B",
    "New transaction received"
)

send_message(
    "Node B",
    "Node C",
    "Transaction forwarded"
)


# ============================================================
# 9. TRUST IN DECENTRALIZED SYSTEMS
# ============================================================

print("\n9. TRUST IN DECENTRALIZED SYSTEMS")

trust_models = {
    "Centralized": "Trust a central authority",
    "Decentralized": "Trust is distributed across participants and rules"
}

for model, explanation in trust_models.items():
    print(model, "->", explanation)


# ============================================================
# 10. CONSENSUS
# ============================================================

print("\n10. CONSENSUS")

nodes = {
    "Node A": "YES",
    "Node B": "YES",
    "Node C": "YES",
    "Node D": "NO"
}

yes_votes = 0

for node, vote in nodes.items():

    print(node, "voted:", vote)

    if vote == "YES":
        yes_votes += 1


print("\nYES votes:", yes_votes)
print("Total nodes:", len(nodes))

if yes_votes > len(nodes) / 2:
    print("Basic majority reached.")
else:
    print("Basic majority not reached.")


# ============================================================
# 11. ADVANTAGES
# ============================================================

print("\n11. POTENTIAL ADVANTAGES")

advantages = [
    "Reduced dependence on a single authority",
    "Fault tolerance",
    "Distributed participation",
    "Transparency in some system designs",
    "Resistance to a single point of failure"
]

for advantage in advantages:
    print("-", advantage)


# ============================================================
# 12. CHALLENGES
# ============================================================

print("\n12. CHALLENGES")

challenges = [
    "Coordination",
    "Scalability",
    "Security",
    "Consensus",
    "Network failures",
    "Data consistency"
]

for challenge in challenges:
    print("-", challenge)


# ============================================================
# 13. DECENTRALIZED TECHNOLOGIES
# ============================================================

print("\n13. DECENTRALIZED TECHNOLOGIES")

technologies = [
    "Peer-to-Peer Networks",
    "Blockchain",
    "Distributed Ledgers",
    "Decentralized Storage",
    "Decentralized Applications",
    "Decentralized Identity"
]

for technology in technologies:
    print("-", technology)


# ============================================================
# 14. BASIC DECENTRALIZED SYSTEM FLOW
# ============================================================

print("\n14. BASIC DECENTRALIZED SYSTEM FLOW")

print("""
Node A
  ↕
Node B ←→ Node C
  ↕       ↕
Node D ←→ Node E

      ↓

Information is shared
across participating nodes.
""")


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("DAY 01 COMPLETED")
print("=" * 60)

print("""
Today you learned:

1. What Decentralization is
2. Centralized systems
3. Decentralized systems
4. Centralized vs decentralized architecture
5. Nodes
6. Peer-to-Peer networks
7. Distributed data
8. Node communication
9. Trust models
10. Consensus
11. Advantages of decentralization
12. Challenges
13. Decentralized technologies
14. Basic decentralized system flow
""")
