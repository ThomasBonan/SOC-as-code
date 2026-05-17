#!/usr/bin/env python3
"""Recalcule l'annotation checksum/script du Deployment risk-engine à partir du
contenu de la ConfigMap soc-risk-engine-app-script.

Pourquoi : ArgoCD sync les ConfigMaps mises à jour, mais K8s ne redémarre pas
le pod si seul un volume ConfigMap change (le contenu monté est rafraîchi mais
le process Python est déjà chargé en mémoire). En portant le hash du script
dans une annotation du pod template, tout changement de script invalide le
template → K8s déclenche un rolling restart.

Usage :
  python3 gitops/environments/lab/risk-engine/_bump-checksums.py

À lancer AVANT chaque commit qui touche configmap-app-script.yaml.

Pour automatiser, ajouter au pre-commit hook ou au target Makefile gitops-sync.
"""

import hashlib
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CONFIGMAP = HERE / "configmap-app-script.yaml"
DEPLOYMENT = HERE / "deployment-risk-engine.yaml"

ANN_LINE_RE = re.compile(
    r'(^\s*checksum/script:\s*")[0-9a-f]{64}(".*$)',
    re.MULTILINE,
)


def compute_sha() -> str:
    with CONFIGMAP.open() as f:
        cm = yaml.safe_load(f)
    script = cm["data"]["risk-engine-app.py"]
    return hashlib.sha256(script.encode()).hexdigest()


def patch_deployment(new_sha: str) -> bool:
    text = DEPLOYMENT.read_text()
    new_text, n = ANN_LINE_RE.subn(
        lambda m: f'{m.group(1)}{new_sha}{m.group(2)}',
        text,
    )
    if n == 0:
        print(
            "ERROR: checksum/script annotation not found in deployment-risk-engine.yaml",
            file=sys.stderr,
        )
        sys.exit(2)
    if new_text == text:
        print(f"checksum/script already up-to-date ({new_sha[:12]}…)")
        return False
    DEPLOYMENT.write_text(new_text)
    print(f"checksum/script updated → {new_sha[:12]}…")
    return True


if __name__ == "__main__":
    patch_deployment(compute_sha())
