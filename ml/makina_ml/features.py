"""
Feature extraction for ML training (Stage 1+).
Called from Rust via subprocess: python -m makina_ml.features <input.json>

Input JSON: list of {code_hash, feature_vector (base64), label}
Output: numpy-compatible feature matrix for GBDT training.
"""

import json
import sys
import base64
import numpy as np


def extract_ast_features(code: str, language: str) -> np.ndarray:
    """
    Extract ~50 hand-crafted features from code for Stage 1 GBDT.
    Does NOT require pre-trained model weights — CPU-native.
    """
    lines = code.splitlines()
    tokens = code.split()

    features = []

    # Structural features
    features.append(len(lines))                          # total lines
    features.append(len(tokens))                         # total tokens
    features.append(len(code))                           # char count
    features.append(code.count("def "))                  # function definitions (Python)
    features.append(code.count("fn "))                   # function definitions (Rust)
    features.append(code.count("class "))                # class definitions
    features.append(code.count("import "))               # imports
    features.append(code.count("use "))                  # Rust use statements

    # Python danger signals
    features.append(int("pickle" in code))
    features.append(int("subprocess" in code))
    features.append(int("os.system" in code))
    features.append(int("eval(" in code))
    features.append(int("exec(" in code))
    features.append(int("yaml.load" in code))
    features.append(int("shell=True" in code))
    features.append(int("hashlib.md5" in code))
    features.append(int("hashlib.sha1" in code))
    features.append(int("random.random" in code))
    features.append(int(".execute(" in code))
    features.append(int("open(" in code))
    features.append(int("requests.get" in code or "requests.post" in code))

    # Rust danger signals
    features.append(int("unsafe {" in code or "unsafe{" in code))
    features.append(int(".unwrap()" in code))
    features.append(int(".expect(" in code))
    features.append(int("Command::new" in code))
    features.append(int("sqlx::query(" in code))
    features.append(code.count(".unwrap()"))             # count of unwraps
    features.append(code.count(".expect("))              # count of expects

    # String interpolation / formatting indicators
    features.append(int('f"' in code or "f'" in code))
    features.append(code.count("{"))                     # brace count (f-string/format)
    features.append(int("% " in code))                  # percent formatting
    features.append(int(".format(" in code))

    # Complexity proxies
    features.append(code.count("if "))
    features.append(code.count("for "))
    features.append(code.count("while "))
    features.append(code.count("try:"))
    features.append(code.count("match "))               # Rust match
    features.append(max(len(line) for line in lines) if lines else 0)  # max line length
    features.append(sum(1 for t in tokens if t.startswith('"') or t.startswith("'")) / max(len(tokens), 1))

    # Padding to fixed length of 50
    while len(features) < 50:
        features.append(0.0)

    return np.array(features[:50], dtype=np.float32)


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m makina_ml.features <input.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        records = json.load(f)

    feature_matrix = []
    labels = []

    for rec in records:
        fv = np.frombuffer(base64.b64decode(rec["feature_vector"]), dtype=np.float32)
        if len(fv) == 50:
            feature_matrix.append(fv)
            labels.append(1 if rec["label"] == "tp" else 0)

    X = np.array(feature_matrix)
    y = np.array(labels)

    output = {"X": X.tolist(), "y": y.tolist(), "n_features": 50}
    print(json.dumps(output))


if __name__ == "__main__":
    main()
