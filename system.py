from auth import AuthService
from audit import AuditService
from crypto import CryptoManager
from nodes import NodeService


class AuditSystem:
    def __init__(self) -> None:
        self.crypto = CryptoManager()
        self.auth = AuthService(token_key=self.crypto.token_key)
        self.nodes = NodeService()
        self.audit = AuditService(crypto_manager=self.crypto, node_service=self.nodes)
