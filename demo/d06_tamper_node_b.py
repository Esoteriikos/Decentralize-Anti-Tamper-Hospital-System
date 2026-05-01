"""Demo 06 - simulate an insider attack on node_b.

Directly opens node_b's append-only ledger file and flips one byte of
the ciphertext field of the third block.  This is the realistic
scenario the assignment asks us to detect: an attacker with shell
access to one of the storage nodes corrupts a stored audit record.

After this script, demo 07 should report the tamper and continue
serving reads from the majority chain (node_a + node_c).
"""

import json
from pathlib import Path

from config import node_data_dir
from demo import banner


def main() -> None:
    banner("Demo 06 - tamper with node_b's chain.jsonl (insider attack)")
    chain_path: Path = node_data_dir("node_b") / "chain.jsonl"
    if not chain_path.exists():
        print(f"[tamper] {chain_path} does not exist; run demos 00 and 01 first.")
        return

    lines = chain_path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 3:
        print(f"[tamper] node_b only has {len(lines)} block(s); need at least 3.  Run demo 01 first.")
        return

    # Pick block index 2 (the third block) and corrupt its ciphertext by
    # flipping the first base64 character.  Any byte change is enough.
    target_index = 2
    block = json.loads(lines[target_index])
    original = block["record"]["ciphertext"]
    flipped = ("B" if original[0] == "A" else "A") + original[1:]
    block["record"]["ciphertext"] = flipped
    lines[target_index] = json.dumps(block, sort_keys=True)
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[tamper] Modified ciphertext of block {block['block_id']} on node_b.")
    print(f"[tamper] Original first base64 char: {original[0]} -> {flipped[0]}")
    print("[tamper] Run demo 07 next to see the integrity report flip to red.")


if __name__ == "__main__":
    main()
