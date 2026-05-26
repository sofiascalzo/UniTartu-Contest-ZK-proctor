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

def fri_commit(evaluations, omega, p, col_name=""):
    layers = []
    current_evals, current_omega, current_n = evaluations[:], omega, len(evaluations)
    transcript = []
    layer_idx = 0

    while current_n > 4:
        dbg(f"FRI {col_name} layer {layer_idx}: n={current_n}, building Merkle tree...")
        leaves = [merkle_hash(str(v).encode()) for v in current_evals]
        tree = build_merkle_tree(leaves)
        root = tree[1]
        layers.append({
            'root': root, 'tree': tree, 'evaluations': current_evals[:],
            'omega': current_omega, 'n': current_n,
        })
        transcript.append(root)
        alpha = fiat_shamir_field(transcript)
        dbg(f"FRI {col_name} layer {layer_idx}: root={root[:16]}..., alpha={alpha}")
        half = current_n // 2
        next_evals = []
        for i in range(half):
            f_x = current_evals[i]
            f_neg_x = current_evals[i + half]
            even = (f_x + f_neg_x) * mod_inv(2, p) % p
            odd = (f_x - f_neg_x) * mod_inv(2 * mod_pow(current_omega, i, p), p) % p
            next_evals.append((even + alpha * odd) % p)
        current_evals = next_evals
        current_omega = mod_pow(current_omega, 2, p)
        current_n = half
        layer_idx += 1

    dbg(f"FRI {col_name} done: {layer_idx} layers, final size={current_n}")
    layers.append({'final_values': current_evals[:], 'n': current_n})
    return {'layers': layers, 'transcript': transcript}

def fri_decommit(commitment, query_indices, p):
    layers = commitment['layers']
    decommitments = []
    for qi in query_indices:
        layer_proofs = []
        idx = qi
        for layer in layers[:-1]:
            n = layer['n']
            idx_mod = idx % n
            sibling_idx = (idx_mod + n // 2) % n
            layer_proofs.append({
                'idx': idx_mod, 'val': layer['evaluations'][idx_mod],
                'sibling_idx': sibling_idx, 'sibling_val': layer['evaluations'][sibling_idx],
                'proof': get_merkle_proof(layer['tree'], idx_mod),
                'sibling_proof': get_merkle_proof(layer['tree'], sibling_idx),
                'root': layer['root'], 'n': n,
            })
            idx = idx_mod % (n // 2)
        decommitments.append(layer_proofs)
    return decommitments


class ProctorSTARK:
    def __init__(self, trace_path=None, trace_data=None):
        if trace_data is not None:
            self.trace_data = trace_data
        elif trace_path is not None:
            with open(trace_path) as f: self.trace_data = json.load(f)
        else:
            raise ValueError("provide trace_path or trace_data")
        self.p = PRIME
        self.trace = self.trace_data['trace']
        self.config_hash = self.trace_data['config_hash']
        self.summary = self.trace_data['summary']

    def _encode_trace(self):
        steps, compliance, violation_counts = [], [], []
        for row in self.trace:
            steps.append(row['step'] % self.p)
            compliance.append(1 if row['is_compliant'] else 0)
            violation_counts.append(row['violation_count'] % self.p)
        return steps, compliance, violation_counts

    def _build_constraint_polynomial(self, compliance, violation_counts):
        n = len(compliance)
        evals = []
        for i in range(n):
            c1 = compliance[i] * (compliance[i] - 1) % self.p
            c2 = 0
            if i > 0:
                diff = (violation_counts[i] - violation_counts[i-1]) % self.p
                c2 = compliance[i] * diff % self.p
            evals.append((c1 + c2) % self.p)
        return evals

    def prove(self, output_path, num_queries=16):
        dbg("=== STARK PROVE START ===")

        dbg("Step 1: Encoding trace to finite field elements...")
        steps, compliance, violation_counts = self._encode_trace()
        n_trace = len(steps)
        n = next_power_of_2(max(n_trace, 8))
        dbg(f"  Trace length: {n_trace}, padded to: {n}")
        dbg(f"  Field: F_p where p = 2^61 - 1 = {self.p}")
        dbg(f"  Compliance column: {compliance[:8]}{'...' if len(compliance) > 8 else ''}")
        dbg(f"  Violation counts:  {violation_counts[:8]}{'...' if len(violation_counts) > 8 else ''}")

        compliance_padded = compliance + [1] * (n - n_trace)
        vc_padded = violation_counts + [violation_counts[-1] if violation_counts else 0] * (n - n_trace)

        dbg("Step 2: Computing NTT interpolation (trace → polynomial coefficients)...")
        omega = find_primitive_root(self.p, n)
        dbg(f"  omega (n-th root of unity, n={n}): {omega}")
        t0 = _time.time()
        compliance_coeffs = interpolate(compliance_padded, omega, self.p)
        vc_coeffs = interpolate(vc_padded, omega, self.p)
        dbg(f"  Interpolated 2 columns in {_time.time()-t0:.3f}s")
        dbg(f"  Compliance poly degree: {len([c for c in compliance_coeffs if c != 0])}")

        dbg("Step 3: Building AIR constraint polynomial...")
        dbg("  Constraint 1: compliance[i] ∈ {0,1}  →  compliance[i]·(compliance[i]-1) = 0")
        dbg("  Constraint 2: if compliant, violations don't increase  →  compliance[i]·(vc[i]-vc[i-1]) = 0")
        constraint_evals = self._build_constraint_polynomial(compliance_padded, vc_padded)
        constraint_coeffs = interpolate(constraint_evals, omega, self.p)
        nonzero = sum(1 for c in constraint_evals if c != 0)
        dbg(f"  Constraint poly nonzero evaluations: {nonzero}/{n}")

        dbg("Step 4: Low Degree Extension (LDE) — blowup factor 2x...")
        blowup = 2
        n_lde = n * blowup
        omega_lde = find_primitive_root(self.p, n_lde)
        dbg(f"  LDE domain size: {n_lde} (trace {n} × blowup {blowup})")
        dbg(f"  omega_lde (root of unity for LDE): {omega_lde}")
        t0 = _time.time()
        compliance_lde = poly_eval_domain(compliance_coeffs, omega_lde, n_lde, self.p)
        vc_lde = poly_eval_domain(vc_coeffs, omega_lde, n_lde, self.p)
        constraint_lde = poly_eval_domain(constraint_coeffs, omega_lde, n_lde, self.p)
        dbg(f"  Evaluated 3 polynomials on LDE domain in {_time.time()-t0:.3f}s")

        dbg("Step 5: FRI commitment phase (polynomial → Merkle tree layers)...")
        t0 = _time.time()
        compliance_commitment = fri_commit(compliance_lde, omega_lde, self.p, "compliance")
        vc_commitment = fri_commit(vc_lde, omega_lde, self.p, "violation_count")
        constraint_commitment = fri_commit(constraint_lde, omega_lde, self.p, "constraint")
        n_layers_c = len(compliance_commitment['layers']) - 1
        n_layers_v = len(vc_commitment['layers']) - 1
        n_layers_r = len(constraint_commitment['layers']) - 1
        dbg(f"  FRI layers: compliance={n_layers_c}, violation_count={n_layers_v}, constraint={n_layers_r}")
        dbg(f"  FRI commitment done in {_time.time()-t0:.3f}s")

        all_roots = (
            [l.get('root','') for l in compliance_commitment['layers'] if 'root' in l] +
            [l.get('root','') for l in vc_commitment['layers'] if 'root' in l] +
            [l.get('root','') for l in constraint_commitment['layers'] if 'root' in l]
        )

        dbg(f"Step 6: Generating {num_queries} FRI query indices (Fiat-Shamir)...")
        query_indices = []
        for i in range(num_queries):
            qi = fiat_shamir(all_roots + [str(i)], n_lde)
            query_indices.append(qi)
        dbg(f"  Query indices: {query_indices[:5]}... ({num_queries} total)")

        dbg("Step 7: FRI decommitment (Merkle proofs for query points)...")
        t0 = _time.time()
        compliance_decommit = fri_decommit(compliance_commitment, query_indices, self.p)
        vc_decommit = fri_decommit(vc_commitment, query_indices, self.p)
        constraint_decommit = fri_decommit(constraint_commitment, query_indices, self.p)
        dbg(f"  Decommitment done in {_time.time()-t0:.3f}s")

        def extract_roots(c): return [l['root'] for l in c['layers'] if 'root' in l]
        def extract_final(c): return c['layers'][-1].get('final_values', [])
        def serialize_decommit(d):
            return [[{
                'idx': lp['idx'], 'val': lp['val'],
                'sibling_idx': lp['sibling_idx'], 'sibling_val': lp['sibling_val'],
                'proof': lp['proof'], 'sibling_proof': lp['sibling_proof'],
                'root': lp['root'], 'n': lp['n'],
            } for lp in qp] for qp in d]

        proof = {
            'version': '1.0',
            'protocol': 'ZK-STARK with FRI',
            'field': {'prime': str(self.p), 'generator': GENERATOR},
            'trace_length': n_trace, 'padded_length': n,
            'lde_length': n_lde, 'blowup_factor': blowup,
            'num_queries': num_queries,
            'public_inputs': {
                'config_hash': self.config_hash,
                'config_hash_field': hash_to_int(self.config_hash),
                'total_events': self.summary['total_events'],
                'is_valid': self.summary['is_valid'],
                'compliance_ratio': self.summary['compliance_ratio'],
                'total_violations': self.summary['total_violations'],
                'profile': self.summary.get('profile', 'unknown'),
            },
            'commitments': {
                'compliance': {'roots': extract_roots(compliance_commitment), 'final_values': extract_final(compliance_commitment)},
                'violation_count': {'roots': extract_roots(vc_commitment), 'final_values': extract_final(vc_commitment)},
                'constraint': {'roots': extract_roots(constraint_commitment), 'final_values': extract_final(constraint_commitment)},
            },
            'query_indices': query_indices,
            'decommitments': {
                'compliance': serialize_decommit(compliance_decommit),
                'violation_count': serialize_decommit(vc_decommit),
                'constraint': serialize_decommit(constraint_decommit),
            },
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(proof, indent=2))
        proof_size = len(json.dumps(proof))
        dbg(f"Step 8: Proof serialized → {proof_size:,} bytes")
        dbg("=== STARK PROVE DONE ===")

        return {
            'proof_path': output_path, 'proof_size_bytes': proof_size,
            'trace_length': n_trace, 'padded_length': n,
            'is_valid': self.summary['is_valid'], 'num_queries': num_queries,
        }

