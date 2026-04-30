from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
NODES_DIR = DATA_DIR / "nodes"
USERS_FILE = DATA_DIR / "users.json"
SECRETS_FILE = DATA_DIR / "secrets.json"

NODE_IDS = ["node_a", "node_b", "node_c"]
ALLOWED_ACTIONS = ["create", "delete", "change", "query", "print", "copy"]

