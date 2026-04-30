from copy import deepcopy

from config import NODE_IDS, NODES_DIR
from errors import IntegrityError
from storage import read_json, write_json


class NodeService:
    def __init__(self) -> None:
        NODES_DIR.mkdir(parents=True, exist_ok=True)
        for node_id in NODE_IDS:
            path = self._node_path(node_id)
            if not path.exists():
                write_json(path, {"node_id": node_id, "records": []})

    @staticmethod
    def _node_path(node_id: str):
        return NODES_DIR / f"{node_id}_ledger.json"

    def reset_ledgers(self) -> None:
        for node_id in NODE_IDS:
            write_json(self._node_path(node_id), {"node_id": node_id, "records": []})

    def read_ledger(self, node_id: str) -> dict:
        return read_json(self._node_path(node_id), default={"node_id": node_id, "records": []})

    def write_ledger(self, node_id: str, ledger: dict) -> None:
        write_json(self._node_path(node_id), ledger)

    def get_all_ledgers(self) -> dict[str, dict]:
        return {node_id: self.read_ledger(node_id) for node_id in NODE_IDS}

    def get_record_count(self) -> int:
        return len(self.read_ledger(NODE_IDS[0])["records"])

    def get_latest_hash(self) -> str:
        self.assert_nodes_match()
        records = self.read_ledger(NODE_IDS[0])["records"]
        if not records:
            return "GENESIS"
        return records[-1]["current_hash"]

    def append_record_to_all_nodes(self, base_record: dict) -> None:
        self.assert_nodes_match()
        for node_id in NODE_IDS:
            ledger = self.read_ledger(node_id)
            record = deepcopy(base_record)
            record["node_id"] = node_id
            ledger["records"].append(record)
            self.write_ledger(node_id, ledger)

    def assert_nodes_match(self) -> None:
        ledgers = self.get_all_ledgers()
        baseline = [self._canonicalize(record) for record in ledgers[NODE_IDS[0]]["records"]]
        for node_id in NODE_IDS[1:]:
            candidate = [self._canonicalize(record) for record in ledgers[node_id]["records"]]
            if candidate != baseline:
                raise IntegrityError(f"Node mismatch detected before write: {node_id} differs from {NODE_IDS[0]}.")

    def tamper_record(self, node_id: str, record_index: int, field: str, new_value: str) -> dict:
        ledger = self.read_ledger(node_id)
        ledger["records"][record_index][field] = new_value
        self.write_ledger(node_id, ledger)
        return ledger["records"][record_index]

    @staticmethod
    def _canonicalize(record: dict) -> dict:
        canonical = dict(record)
        canonical.pop("node_id", None)
        return canonical

