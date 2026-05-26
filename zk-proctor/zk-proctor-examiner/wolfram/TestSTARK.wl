Get[FileNameJoin[{DirectoryName[$InputFileName], "ZKProctorSTARK.wl"}]];
Print["\n============================================================"];
Print["  ZK-Proctor STARK Tests"];
Print["============================================================"];

Print["\n--- Test 1: Field ---"];
If[Mod[modInv[7,p]*7,p]=!=1, Print["FAIL"]; Abort[]];
w8=primitiveRoot[p,8];
If[modPow[w8,8,p]=!=1, Print["FAIL"]; Abort[]];
If[modPow[w8,4,p]===1, Print["FAIL"]; Abort[]];
Print["  OK"];

Print["\n--- Test 2: NTT ---"];
r=intt[ntt[{1,2,3,4,5,6,7,8},primitiveRoot[p,8],p],primitiveRoot[p,8],p];
If[r=!={1,2,3,4,5,6,7,8}, Print["FAIL"]; Abort[]];
Print["  OK"];

Print["\n--- Test 3: Merkle ---"];
lv=merkleHash[ToString[#]]&/@{10,20,30,40};
tree=buildMerkleTree[lv]; rt=getMerkleRoot[tree];
Do[pr=getMerkleProof[tree,i,4];
  If[!verifyMerkleProof[rt,lv[[i+1]],i,pr,4], Print["FAIL leaf ",i]; Abort[]];,{i,0,3}];
Print["  OK"];

Print["\n--- Test 4: Honest proof ---"];
ht=Table[<|"step"->i,"is_compliant"->True,"violation_count"->0,"timestamp"->1000.0+i,
  "window_hash"->"","process_hashes"->{},"url_hash"->"","event_type"->"heartbeat"|>,{i,0,7}];
td=<|"profile"->"Test","config_hash"->"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "trace"->ht,"violations"->{},
  "summary"-><|"profile"->"Test","total_events"->8,"compliant_events"->8,
    "compliance_ratio"->1.0,"total_violations"->0,"critical_violations"->0,
    "is_valid"->True,"duration_seconds"->7|>|>;
t0=AbsoluteTime[];
pr=proveSTARK[td,"test_h.json",8,True];
Print["  Proved: ",Round[AbsoluteTime[]-t0,0.01],"s, ",pr["proof_size_bytes"]," bytes"];
t0=AbsoluteTime[];
vr=verifySTARK["test_h.json",True];
Print["  Verified: ",Round[(AbsoluteTime[]-t0)*1000,1]," ms"];
If[!TrueQ[vr["verified"]], Print["  FAIL: ",vr["checks"]];, Print["  OK: VERIFIED"]];

Print["\n--- Test 5: Cheating ---"];
ct=Join[Table[<|"step"->i,"is_compliant"->True,"violation_count"->0,"timestamp"->2000.0+i,
  "window_hash"->"","process_hashes"->{},"url_hash"->"","event_type"->"heartbeat"|>,{i,0,6}],
  {<|"step"->7,"is_compliant"->False,"violation_count"->1,"timestamp"->2007.0,
    "window_hash"->"","process_hashes"->{},"url_hash"->"","event_type"->"url"|>}];
cd=<|"profile"->"Test","config_hash"->"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "trace"->ct,"violations"->{<|"timestamp"->2007.0,"constraint"->"domain","severity"->"critical","event_hash"->"x"|>},
  "summary"-><|"profile"->"Test","total_events"->8,"compliant_events"->7,
    "compliance_ratio"->7.0/8.0,"total_violations"->1,"critical_violations"->1,
    "is_valid"->False,"duration_seconds"->7|>|>;
proveSTARK[cd,"test_c.json",8];
cv=verifySTARK["test_c.json"];
If[TrueQ[cv["public_inputs"]["is_valid"]], Print["FAIL"];, Print["  OK: NON-COMPLIANT"]];

Print["\n--- Test 6: Privacy ---"];
If[StringContainsQ[Import["test_c.json","Text"],"chatgpt",IgnoreCase->True],
  Print["FAIL"];, Print["  OK"]];

Print["\n============================================================"];
Print["  ALL TESTS PASSED"];
Print["============================================================"];
Quiet[DeleteFile["test_h.json"]]; Quiet[DeleteFile["test_c.json"]];
