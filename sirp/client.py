import secrets
import hashlib
import re
from typing import Union
from .parameters import ParameterMixin
from .sirp import SirpMixin

class Client(ParameterMixin, SirpMixin):
    def __init__(self, group: int = 2048):
        if not isinstance(group, int):
            raise ValueError('group must be an Integer')
        if group not in [1024, 1536, 2048, 3072, 4096, 6144, 8192]:
            raise ValueError('group must be a known group size')

        self.N, self.g, self.hash = self.Ng(group)
        self.k = self.calc_k(self.N, self.g, self.hash)
        self.a = None
        self.A = None
        self.S = None
        self.K = None
        self.M = None
        self.H_AMK = None

    def start_authentication(self) -> str:
        self.a = int(secrets.token_hex(256), 16)
        self.A = self.num_to_hex(self.calc_A(self.a, self.N, self.g))
        return self.A

    def process_challenge(self, username: str, password: str, xsalt: str, xbb: str, is_password_encrypted: bool = False) -> Union[str, bool]:
        if not isinstance(username, str) or not username:
            raise ValueError('username must be a non-empty string')
        if not isinstance(password, str) or not password:
            raise ValueError('password must be a non-empty string')
        if not isinstance(xsalt, str) or not re.match(r'^[a-fA-F0-9]+$', xsalt):
            raise ValueError('xsalt must be a hex string')
        if not isinstance(xbb, str) or not re.match(r'^[a-fA-F0-9]+$', xbb):
            raise ValueError('xbb must be a hex string')

        bb = int(xbb, 16)

        if bb % self.N == 0:
            return False

        if is_password_encrypted:
            x = self.calc_x_hex(password, xsalt, self.hash)
        else:
            x = self.calc_x(username, password, xsalt, self.hash)
        u = self.calc_u(self.A, xbb, self.N, self.hash)

        if u == 0:
            return False

        self.S = self.num_to_hex(self.calc_client_S(bb, self.a, self.k, x, u, self.N, self.g))
        self.K = self.sha_hex(self.S, self.hash)

        self.M = self.calc_M(self.N, self.g, username, xsalt, self.A, xbb, self.K, self.hash)

        self.H_AMK = self.num_to_hex(self.calc_H_AMK(self.A, self.M, self.K, self.hash))

        return self.M

    def verify(self, server_HAMK: str) -> bool:
        if not self.H_AMK or not server_HAMK:
            return False
        if not isinstance(server_HAMK, str) or not re.match(r'^[a-fA-F0-9]+$', server_HAMK):
            return False

        return self.secure_compare(hashlib.sha256(self.H_AMK.encode()).hexdigest(),
                                   hashlib.sha256(server_HAMK.encode()).hexdigest())
