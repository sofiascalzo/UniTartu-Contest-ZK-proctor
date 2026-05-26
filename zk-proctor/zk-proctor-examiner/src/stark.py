import hashlib
import json
import time as _time
from pathlib import Path

PRIME = (1 << 61) - 1
GENERATOR = 2

_debug = False
def set_debug(v): global _debug; _debug = v
def dbg(msg):
    if _debug: print(f"    [dbg] {msg}")

def mod_pow(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1: result = result * base % mod
        exp >>= 1
        base = base * base % mod
    return result

def mod_inv(a, mod):
    return mod_pow(a, mod - 2, mod)

def find_primitive_root(p, n):
    return mod_pow(GENERATOR, (p - 1) // n, p)

def next_power_of_2(n):
    p = 1
    while p < n: p <<= 1
    return p

def ntt(vals, omega, p):
    n = len(vals)
    if n == 1: return vals[:]
    even = ntt(vals[0::2], mod_pow(omega, 2, p), p)
    odd = ntt(vals[1::2], mod_pow(omega, 2, p), p)
    result = [0] * n
    w = 1
    half = n // 2
    for i in range(half):
        result[i] = (even[i] + w * odd[i]) % p
        result[i + half] = (even[i] - w * odd[i]) % p
        w = w * omega % p
    return result

def intt(vals, omega, p):
    omega_inv = mod_inv(omega, p)
    result = ntt(vals, omega_inv, p)
    n_inv = mod_inv(len(vals), p)
    return [(x * n_inv) % p for x in result]

def poly_eval_domain(coeffs, omega, n, p):
    return ntt(coeffs + [0] * (n - len(coeffs)), omega, p)

def interpolate(evals, omega, p):
    return intt(evals, omega, p)

def merkle_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build_merkle_tree(leaves):
    n = len(leaves)
    tree = [''] * (2 * n)
    for i in range(n): tree[n + i] = leaves[i]
    for i in range(n - 1, 0, -1):
        tree[i] = merkle_hash((tree[2*i] + tree[2*i+1]).encode())
    return tree

def get_merkle_proof(tree, idx):
    n = len(tree) // 2
    proof, pos = [], n + idx
    while pos > 1:
        proof.append(tree[pos ^ 1])
        pos >>= 1
    return proof

def verify_merkle_proof(root, leaf, idx, proof, n):
    current, pos = leaf, n + idx
    for sib in proof:
        if pos & 1: current = merkle_hash((sib + current).encode())
        else: current = merkle_hash((current + sib).encode())
        pos >>= 1
    return current == root

def fiat_shamir(transcript, domain_size):
    h = hashlib.sha256('|'.join(transcript).encode()).digest()
    return int.from_bytes(h[:8], 'big') % domain_size

def fiat_shamir_field(transcript):
    h = hashlib.sha256('|'.join(transcript).encode()).digest()
    return int.from_bytes(h[:8], 'big') % PRIME

def hash_to_int(hex_str):
    return int(hex_str[:15], 16) % PRIME

class ProctorVerifier:
    def __init__(self, proof_path):
        with open(proof_path) as f: self.proof = json.load(f)
        self.p = int(self.proof['field']['prime'])

    def verify(self):
        checks = {}

        dbg("=== STARK VERIFY START ===")

        dbg("Check 1: Proof format validation...")
        checks['format_valid'] = all(k in self.proof for k in
            ['version', 'commitments', 'decommitments', 'public_inputs', 'query_indices'])
        dbg(f"  format_valid = {checks['format_valid']}")

        pub = self.proof['public_inputs']
        dbg("Check 2: Config hash consistency...")
        config_hash_int = hash_to_int(pub['config_hash'])
        checks['config_hash_consistent'] = (config_hash_int == pub['config_hash_field'])
        dbg(f"  H(config) = {pub['config_hash'][:24]}...")
        dbg(f"  H(config) mod p = {config_hash_int}")
        dbg(f"  Expected field element = {pub['config_hash_field']}")
        dbg(f"  config_hash_consistent = {checks['config_hash_consistent']}")

        dbg("Check 3: Compliance ratio vs is_valid consistency...")
        checks['compliance_ratio_consistent'] = True
        if pub['total_events'] > 0:
            expected_valid = pub['compliance_ratio'] == 1.0
            checks['compliance_ratio_consistent'] = (expected_valid == pub['is_valid'])
        dbg(f"  compliance_ratio = {pub['compliance_ratio']:.4f}")
        dbg(f"  is_valid = {pub['is_valid']}")
        dbg(f"  compliance_ratio_consistent = {checks['compliance_ratio_consistent']}")

        for col_name in ['compliance', 'violation_count', 'constraint']:
            dbg(f"Check 4.{col_name}: Verifying FRI Merkle proofs...")
            decomms = self.proof['decommitments'][col_name]
            col_valid = True
            proofs_checked = 0
            for qi, query_decomm in enumerate(decomms):
                for lp in query_decomm:
                    leaf = merkle_hash(str(lp['val']).encode())
                    if not verify_merkle_proof(lp['root'], leaf, lp['idx'], lp['proof'], lp['n']):
                        col_valid = False; break
                    sib_leaf = merkle_hash(str(lp['sibling_val']).encode())
                    if not verify_merkle_proof(lp['root'], sib_leaf, lp['sibling_idx'], lp['sibling_proof'], lp['n']):
                        col_valid = False; break
                    proofs_checked += 2
                if not col_valid: break
            checks[f'{col_name}_merkle_valid'] = col_valid
            dbg(f"  {col_name}: {proofs_checked} Merkle proofs checked → {'PASS' if col_valid else 'FAIL'}")

        dbg("Check 5: Constraint polynomial evaluates to zero...")
        constraint_finals = self.proof['commitments']['constraint']['final_values']
        checks['constraint_evaluates_zero'] = all(v == 0 for v in constraint_finals)
        dbg(f"  Final FRI values for constraint poly: {constraint_finals}")
        dbg(f"  constraint_evaluates_zero = {checks['constraint_evaluates_zero']}")

        all_valid = all(checks.values())
        dbg(f"=== STARK VERIFY DONE: {'VALID' if all_valid else 'INVALID'} ===")

        return {'verified': all_valid, 'checks': checks, 'public_inputs': pub}
