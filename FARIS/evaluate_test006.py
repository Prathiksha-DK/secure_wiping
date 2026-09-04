import pandas as pd
import os

recovered = pd.read_csv(r"D:\Recovery\FARIS\cases\TEST-006\reports\recovered_artifacts_TEST-006.csv")
gt1 = pd.read_csv(r"D:\Recovery\FARIS\test01_ground_truth.csv")
gt2 = pd.read_csv(r"D:\Recovery\FARIS\test02_ground_truth.csv")

# Normalize recovered data
recovered["File Name"] = recovered["File Name"].astype(str).str.strip()
recovered["Size (Bytes)"] = pd.to_numeric(recovered["Size (Bytes)"], errors="coerce")

# ------------------------------------------------------------
# TEST-1: filename + exact size
# ------------------------------------------------------------
gt1["Target"] = gt1["FullName"].astype(str).apply(os.path.basename)
gt1["Length"] = pd.to_numeric(gt1["Length"], errors="coerce")

test1 = []

for _, r in gt1.iterrows():
    matches = recovered[
        (recovered["File Name"].str.lower() == r["Target"].lower()) &
        (recovered["Size (Bytes)"] == r["Length"]) &
        (recovered["Validation Status"].astype(str).str.upper() == "VALID")
    ]

    test1.append({
        "Target": r["Target"],
        "Expected Size": int(r["Length"]),
        "Status": "EXACT_RECOVERED" if len(matches) > 0 else "UNRECOVERED",
        "Provenance Entries": len(matches)
    })

test1 = pd.DataFrame(test1)

# ------------------------------------------------------------
# TEST-2: exact SHA-256
# ------------------------------------------------------------
gt2["Target"] = gt2["Name"].astype(str).str.strip()
gt2["SHA256"] = gt2["SHA256"].astype(str).str.strip().str.lower()

recovered["SHA256_norm"] = (
    recovered["SHA-256"]
    .astype(str)
    .str.strip()
    .str.lower()
)

test2 = []

for _, r in gt2.iterrows():
    matches = recovered[
        (recovered["SHA256_norm"] == r["SHA256"]) &
        (recovered["Validation Status"].astype(str).str.upper() == "VALID")
    ]

    test2.append({
        "Target": r["Target"],
        "Expected Size": int(r["Length"]),
        "Status": "EXACT_RECOVERED" if len(matches) > 0 else "UNRECOVERED",
        "Provenance Entries": len(matches)
    })

test2 = pd.DataFrame(test2)

# ------------------------------------------------------------
# COMBINED RESULTS
# ------------------------------------------------------------
all_targets = pd.concat([
    test1.assign(Test="TEST-1"),
    test2.assign(Test="TEST-2")
], ignore_index=True)

exact = (all_targets["Status"] == "EXACT_RECOVERED").sum()
total = len(all_targets)
unrecovered = total - exact

print("\n" + "="*75)
print("FARIS TEST-006 — FINAL GROUND-TRUTH EVALUATION")
print("="*75)

print(f"TEST-1 targets       : {len(test1)}")
print(f"TEST-1 recovered     : {(test1.Status == 'EXACT_RECOVERED').sum()}")
print(f"TEST-1 unrecovered   : {(test1.Status == 'UNRECOVERED').sum()}")
print(f"TEST-1 recovery rate : {(test1.Status == 'EXACT_RECOVERED').mean()*100:.2f}%")

print()

print(f"TEST-2 targets       : {len(test2)}")
print(f"TEST-2 recovered     : {(test2.Status == 'EXACT_RECOVERED').sum()}")
print(f"TEST-2 unrecovered   : {(test2.Status == 'UNRECOVERED').sum()}")
print(f"TEST-2 recovery rate : {(test2.Status == 'EXACT_RECOVERED').mean()*100:.2f}%")

print("\n" + "-"*75)

print(f"TOTAL UNIQUE TARGETS : {total}")
print(f"EXACTLY RECOVERED    : {exact}")
print(f"UNRECOVERED          : {unrecovered}")
print(f"FILE RECOVERY RATE   : {exact/total*100:.2f}%")

print("\n" + "="*75)
print("TARGET-BY-TARGET RESULT")
print("="*75)

print(all_targets[
    ["Test", "Target", "Expected Size", "Status", "Provenance Entries"]
].to_string(index=False))

print("\n" + "="*75)
