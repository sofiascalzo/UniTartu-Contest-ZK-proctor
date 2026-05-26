p = 2013265921;
g = 11;

modPow[base_, exp_, mod_] := PowerMod[base, exp, mod]
modInv[a_, mod_] := PowerMod[a, mod - 2, mod]
primitiveRoot[prime_, n_] := modPow[g, (prime - 1)/n, prime]
nextPow2[n_] := 2^Ceiling[Log2[Max[n, 2]]]
merkleHash[data_String] := IntegerString[Hash[data, "SHA256"], 16, 64]
bitReverse[i_Integer, bits_Integer] := FromDigits[Reverse[IntegerDigits[i, 2, bits]], 2]

ntt[vals_List, omega_, prime_] := Module[
  {n = Length[vals], a, bits, half, m, wm, w, t, u},
  bits = IntegerLength[n - 1, 2];
  a = Table[vals[[bitReverse[i, bits] + 1]], {i, 0, n - 1}];
  m = 2;
  While[m <= n, half = m/2; wm = modPow[omega, n/m, prime];
    Do[w = 1; Do[
      t = Mod[w*a[[k + j + half]], prime]; u = a[[k + j]];
      a[[k + j]] = Mod[u + t, prime];
      a[[k + j + half]] = Mod[u - t + prime, prime];
      w = Mod[w*wm, prime];, {j, 0, half - 1}];, {k, 1, n, m}];
    m *= 2]; a]

intt[vals_List, omega_, prime_] := Module[{r, nI},
  r = ntt[vals, modInv[omega, prime], prime]; nI = modInv[Length[vals], prime];
  Mod[# * nI, prime] & /@ r]

polyEvalDomain[c_List, w_, n_, pr_] := ntt[Join[c, Table[0, n - Length[c]]], w, pr]
interpolate[e_List, w_, pr_] := intt[e, w, pr]

buildMerkleTree[leaves_List] := Module[{n = Length[leaves], tree},
  tree = Table["", {2*n + 1}];
  Do[tree[[n + i + 1]] = leaves[[i + 1]], {i, 0, n - 1}];
  Do[tree[[i + 1]] = merkleHash[tree[[2 i + 1]] <> tree[[2 i + 2]]], {i, n - 1, 1, -1}];
  tree]

getMerkleRoot[tree_] := tree[[2]]

getMerkleProof[tree_List, idx0_Integer, n_Integer] := Module[
  {proof = {}, pos, sib},
  pos = n + idx0;
  While[pos > 1, sib = BitXor[pos, 1];
    AppendTo[proof, tree[[sib + 1]]];
    pos = BitShiftRight[pos, 1]];
  proof]

verifyMerkleProof[root_String, leaf_String, idx0_Integer, proof_List, n_Integer] :=
  Module[{current = leaf, pos = n + idx0},
    Do[current = If[OddQ[pos], merkleHash[sib <> current], merkleHash[current <> sib]];
      pos = BitShiftRight[pos, 1];, {sib, proof}];
    current === root]

fiatShamir[t_List, d_Integer] := Mod[Hash[StringRiffle[ToString /@ t, "|"], "SHA256"], d]
fiatShamirField[t_List] := Mod[Hash[StringRiffle[ToString /@ t, "|"], "SHA256"], p]
hashToInt[h_String] := Mod[FromDigits[StringTake[h, Min[8, StringLength[h]]], 16], p]

friCommit[evals_List, omega_, prime_, debug_: False] :=
  Module[{layers = {}, ce, co, cn, tr = {}, li = 0, lv, tree, root, alpha, half, ne, fX, fNX, ev, od},
    ce = evals; co = omega; cn = Length[evals];
    While[cn > 4,
      If[debug, Print["    [dbg] FRI layer ", li, ": n=", cn]];
      lv = merkleHash[ToString[#]] & /@ ce;
      tree = buildMerkleTree[lv]; root = getMerkleRoot[tree];
      AppendTo[layers, <|"root" -> root, "tree" -> tree, "evaluations" -> ce, "n" -> cn|>];
      AppendTo[tr, root]; alpha = fiatShamirField[tr]; half = cn/2;
      ne = Table[fX = ce[[i]]; fNX = ce[[i + half]];
        ev = Mod[(fX + fNX)*modInv[2, prime], prime];
        od = Mod[(fX - fNX)*modInv[2*modPow[co, i - 1, prime], prime], prime];
        Mod[ev + alpha*od, prime], {i, 1, half}];
      ce = ne; co = modPow[co, 2, prime]; cn = half; li++];
    AppendTo[layers, <|"finalValues" -> ce, "n" -> cn|>];
    <|"layers" -> layers, "transcript" -> tr|>]

friDecommit[commit_Association, qis_List] := Module[{layers, ds = {}},
  layers = commit["layers"];
  Do[Module[{lps = {}, idx0 = qi},
    Do[Module[{n, im, sm},
      n = layer["n"]; im = Mod[idx0, n]; sm = Mod[im + n/2, n];
      AppendTo[lps, <|"idx" -> im, "val" -> layer["evaluations"][[im + 1]],
        "sibIdx" -> sm, "sibVal" -> layer["evaluations"][[sm + 1]],
        "proof" -> getMerkleProof[layer["tree"], im, n],
        "sibProof" -> getMerkleProof[layer["tree"], sm, n],
        "root" -> layer["root"], "n" -> n|>];
      idx0 = Mod[im, n/2];], {layer, Most[layers]}];
    AppendTo[ds, lps];], {qi, qis}]; ds]

encodeTrace[rows_List] := {
  If[TrueQ[#["is_compliant"]], 1, 0] & /@ rows,
  Mod[#["violation_count"], p] & /@ rows}

buildConstraintPoly[comp_List, vc_List] := Table[Module[{c1, c2},
  c1 = Mod[comp[[i]]*(comp[[i]] - 1), p];
  c2 = If[i > 1, Mod[comp[[i]]*Mod[vc[[i]] - vc[[i - 1]], p], p], 0];
  Mod[c1 + c2, p]], {i, Length[comp]}]

proveSTARK[td_Association, out_String, nq_: 16, dbg_: False] :=
  Module[{tr, ch, sm, co, vc, nt, n, cp, vp, w, cc, vcc, ce, cec, bl = 2, nl, wl,
          cl, vl, rl, cC, vC, rC, ar, qi, cD, vD, rD, pf, ps, t0, eR, eF, sD},
    tr = td["trace"]; ch = td["config_hash"]; sm = td["summary"];
    If[dbg, Print["=== STARK PROVE ==="]];
    {co, vc} = encodeTrace[tr]; nt = Length[co]; n = nextPow2[Max[nt, 8]];
    If[dbg, Print["  Trace: ", nt, " -> pad: ", n]];
    cp = Join[co, Table[1, n - nt]];
    vp = Join[vc, Table[If[Length[vc] > 0, Last[vc], 0], n - nt]];
    w = primitiveRoot[p, n];
    If[dbg, Print["  omega^", n, " = ", modPow[w, n, p]]];
    t0 = AbsoluteTime[];
    cc = interpolate[cp, w, p]; vcc = interpolate[vp, w, p];
    If[dbg, Print["  NTT: ", Round[AbsoluteTime[] - t0, 0.001], "s"]];
    ce = buildConstraintPoly[cp, vp]; cec = interpolate[ce, w, p];
    If[dbg, Print["  Constraint nonzero: ", Count[ce, _?(# != 0 &)]]];
    nl = n*bl; wl = primitiveRoot[p, nl];
    t0 = AbsoluteTime[];
    cl = polyEvalDomain[cc, wl, nl, p]; vl = polyEvalDomain[vcc, wl, nl, p];
    rl = polyEvalDomain[cec, wl, nl, p];
    If[dbg, Print["  LDE(", nl, "): ", Round[AbsoluteTime[] - t0, 0.001], "s"]];
    t0 = AbsoluteTime[];
    cC = friCommit[cl, wl, p, dbg]; vC = friCommit[vl, wl, p, dbg]; rC = friCommit[rl, wl, p, dbg];
    If[dbg, Print["  FRI: ", Round[AbsoluteTime[] - t0, 0.001], "s"]];
    eR[c_] := Lookup[#, "root"] & /@ Select[c["layers"], KeyExistsQ[#, "root"] &];
    eF[c_] := c["layers"][[-1]]["finalValues"];
    ar = Join[eR[cC], eR[vC], eR[rC]];
    qi = Table[fiatShamir[Append[ar, ToString[i]], nl], {i, 0, nq - 1}];
    t0 = AbsoluteTime[];
    cD = friDecommit[cC, qi]; vD = friDecommit[vC, qi]; rD = friDecommit[rC, qi];
    If[dbg, Print["  Decommit: ", Round[AbsoluteTime[] - t0, 0.001], "s"]];
    sD[d_] := Map[Function[q, Map[Function[l, <|"idx"->l["idx"],"val"->l["val"],
      "sibIdx"->l["sibIdx"],"sibVal"->l["sibVal"],"proof"->l["proof"],
      "sibProof"->l["sibProof"],"root"->l["root"],"n"->l["n"]|>], q]], d];
    pf = <|"version"->"1.0","protocol"->"ZK-STARK with FRI (Wolfram)",
      "field"-><|"prime"->ToString[p],"generator"->g|>,
      "trace_length"->nt,"padded_length"->n,"lde_length"->nl,"blowup_factor"->bl,"num_queries"->nq,
      "public_inputs"-><|"config_hash"->ch,"config_hash_field"->hashToInt[ch],
        "total_events"->sm["total_events"],"is_valid"->sm["is_valid"],
        "compliance_ratio"->sm["compliance_ratio"],"total_violations"->sm["total_violations"],
        "profile"->sm["profile"]|>,
      "commitments"-><|"compliance"-><|"roots"->eR[cC],"final_values"->eF[cC]|>,
        "violation_count"-><|"roots"->eR[vC],"final_values"->eF[vC]|>,
        "constraint"-><|"roots"->eR[rC],"final_values"->eF[rC]|>|>,
      "query_indices"->qi,
      "decommitments"-><|"compliance"->sD[cD],"violation_count"->sD[vD],"constraint"->sD[rD]|>|>;
    Export[out, pf, "RawJSON"]; ps = FileByteCount[out];
    If[dbg, Print["  Proof: ", ps, " bytes\n=== DONE ==="]];
    <|"proof_path"->out,"proof_size_bytes"->ps,"trace_length"->nt,
      "padded_length"->n,"is_valid"->sm["is_valid"],"num_queries"->nq|>]

verifySTARK[path_String, dbg_: False] := Module[
  {pf, ck = <||>, pub, chi, cn, dm, cv, pc, lf, sl, cf, av},
  pf = Import[path, "RawJSON"];
  If[dbg, Print["=== VERIFY ==="]];
  ck["format_valid"] = AssociationQ[pf] && AllTrue[{"version","commitments","public_inputs","query_indices"}, KeyExistsQ[pf,#]&];
  pub = pf["public_inputs"]; chi = hashToInt[pub["config_hash"]];
  ck["config_hash"] = (chi === pub["config_hash_field"]);
  ck["compliance_ratio"] = If[pub["total_events"] > 0,
    (pub["compliance_ratio"] == 1.0) == TrueQ[pub["is_valid"]], True];
  Do[dm = pf["decommitments"][cn]; cv = True; pc = 0;
    If[ListQ[dm], Do[If[ListQ[qd], Do[
      lf = merkleHash[ToString[lp["val"]]];
      If[!verifyMerkleProof[lp["root"], lf, lp["idx"], lp["proof"], lp["n"]], cv = False; Break[]];
      sl = merkleHash[ToString[lp["sibVal"]]];
      If[!verifyMerkleProof[lp["root"], sl, lp["sibIdx"], lp["sibProof"], lp["n"]], cv = False; Break[]];
      pc += 2;, {lp, qd}]]; If[!cv, Break[]];, {qd, dm}]];
    ck[cn <> "_merkle"] = cv;
    If[dbg, Print["  ", cn, ": ", pc, " proofs -> ", If[cv, "PASS", "FAIL"]]];,
    {cn, {"compliance", "violation_count", "constraint"}}];
  cf = pf["commitments"]["constraint"]["final_values"];
  ck["constraint_zero"] = ListQ[cf] && AllTrue[cf, # === 0 &];
  If[dbg, Print["  constraint=0: ", ck["constraint_zero"]]];
  av = AllTrue[Values[ck], TrueQ];
  If[dbg, Print["=== ", If[av, "VALID", "INVALID"], " ==="]];
  <|"verified" -> av, "checks" -> ck, "public_inputs" -> pub|>]

Print["ZK-Proctor STARK/FRI loaded"];
Print["Field: p=", p, " (15*2^27+1), g=", g];
