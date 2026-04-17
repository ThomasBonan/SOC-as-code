# Procédure de redéploiement from-scratch — SOC-as-code

## Prérequis

| Outil | Version min | Vérification |
|-------|-------------|--------------|
| tofu / terraform | 1.6+ | `tofu version` |
| ansible-playbook | 2.15+ | `ansible-playbook --version` |
| kubectl | 1.30+ | `kubectl version --client` |
| helm | 3.14+ | `helm version` |
| jq | 1.6+ | `jq --version` |
| yq | 4.x | `yq --version` |

Variables d'environnement requises :
```bash
set -a && source /etc/soc-as-code/.env && set +a
# Vérifier : PROXMOX_URL, PROXMOX_USER, PROXMOX_TOKEN_ID, PROXMOX_TOKEN_SECRET
```

## Déploiement complet (from-scratch)

```bash
make deploy
```

**Durée estimée : 45–75 minutes** selon les ressources Proxmox.

La chaîne complète :

```
preflight          → vérification binaires + accès Proxmox
iac-apply          → VMs Proxmox (tofu apply)
wait-vms           → attendre SSH sur master (10.0.20.10)
k8s-bootstrap      → 00→70 : K8s cluster (prereqs, binaries, control-plane, CNI, workers, post)
wait-nodes         → tous les nœuds Ready
vault-deploy       → Vault 1.17 + ESO (75)
monitoring         → kube-prometheus-stack (76)
argocd             → ArgoCD + soc-app-of-apps (77)
wait-infra-synced  → MetalLB, Longhorn, cert-manager, ingress-nginx Synced+Healthy
wait-soc-apps-synced → Cortex, TheHive, MISP Redis, Shuffle Synced+Healthy (ArgoCD)
databases          → MariaDB MISP (80)
wazuh              → Wazuh manager (90)
misp               → MISP core + attente Redis ArgoCD (100)
cortex             → attente infra-cortex ArgoCD (110)
thehive            → attente infra-thehive ArgoCD (120)
soc-config         → TheHive custom fields + Cortex analyzers (130)
soc-smoke          → smoke tests de base (140)
netpol             → NetworkPolicies (150)
mtls               → mTLS inter-services (155)
wait-argocd-synced → soc-apps, soc-infra, soc-security, soc-eso
foundations        → RBAC / ServiceAccounts (170)
automation         → Wazuh→Shuffle integration, 1er passage (180)
shuffle            → Shuffle SOAR configure + workflows (185)
automation-rerun   → 2e passage automation pour webhook Wazuh (180)
risk-engine        → Risk Engine Flask (190)
compliance         → Audit conformité (200)
selftest           → E2E selftest pipeline complet (210)
```

## Déploiement partiel (cluster K8s existant)

```bash
make deploy DEPLOY_IAC=0
```

Saute `iac-apply`, `wait-vms`, `k8s-bootstrap`. Démarre directement à `wait-nodes`.

## Reprendre après un échec

Identifier l'étape en erreur dans les logs, puis lancer directement la cible correspondante :

```bash
# Exemple : reprendre depuis TheHive
make thehive soc-config soc-smoke mtls foundations automation shuffle automation-rerun risk-engine compliance selftest
```

Ou si l'échec est dans ArgoCD sync :
```bash
kubectl --kubeconfig ansible/playbooks/artifacts/admin.conf \
  -n argocd get applications
# Forcer un sync si bloqué
kubectl --kubeconfig ansible/playbooks/artifacts/admin.conf \
  -n argocd patch application infra-thehive \
  --type merge -p '{"operation":{"sync":{}}}'
```

## Validation post-déploiement

### 1. Nœuds K8s

```bash
kubectl --kubeconfig ansible/playbooks/artifacts/admin.conf get nodes -o wide
# Attendu : 1 master + 3 workers Ready
```

### 2. ArgoCD — toutes les apps Synced+Healthy

```bash
kubectl --kubeconfig ansible/playbooks/artifacts/admin.conf \
  -n argocd get applications \
  -o custom-columns='NAME:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status'
# Attendu : toutes Synced / Healthy (sauf soc-eso Degraded si Vault pas encore init)
```

### 3. Pipeline SOC — selftest E2E

```bash
make selftest
# Score attendu : 16–20 → décision "reviewed"
# Score 0 → Shuffle n'a pas appelé le risk-engine (vérifier 180-rerun)
```

### 4. Accès web

| Service | URL | Creds |
|---------|-----|-------|
| ArgoCD | https://argocd.apps.soc.lab | admin / voir Vault |
| TheHive | https://thehive.apps.soc.lab | admin@thehive.local |
| Cortex | https://cortex.apps.soc.lab | admin |
| MISP | https://misp.apps.soc.lab | admin@admin.test |
| Shuffle | https://shuffle.apps.soc.lab | admin |
| Wazuh | https://wazuh.apps.soc.lab | admin |
| Grafana | https://grafana.apps.soc.lab | admin |

## Destruction du lab

```bash
make destroy-lab CONFIRM=yes
# Détruit TOUTES les VMs Proxmox. Irréversible.
```

## Pièges connus

### Dépendance circulaire 180→185→180

La chaîne `make deploy` encode correctement : `automation → shuffle → automation-rerun`.
**Ne jamais lancer 185 avant 180.**

### TheHive retourne HTTP 200 + "OK" (pas de liste)

```python
# Toujours vérifier avant de traiter les résultats
if isinstance(result, list):
    process(result)
```

### CSRF Cortex

Séquence auth obligatoire :
1. `POST /login`
2. `GET /user/current` → déclenche le cookie `CORTEX-XSRF-TOKEN`
3. Tous les POST suivants avec `Cookie` + header `X-XSRF-TOKEN` + `Csrf-Token: nocheck`

### Fichiers éphémères Wazuh

Ces fichiers disparaissent au redémarrage du pod :
- `/var/ossec/etc/ossec.conf`
- `/var/ossec/etc/rules/soc_selftest_rules.xml`

Correction : `ansible-playbook ansible/playbooks/180-soc-automation.yml --tags integration`

### Score selftest = 0

Shuffle n'a pas appelé le risk-engine. Vérifier :
1. Le webhook Wazuh est bien configuré (180-rerun)
2. Le workflow `alert-triage` est actif dans Shuffle
3. `kubectl logs -n soc-shuffle -l app=shuffle-backend --tail=50`

## Architecture de déploiement

```
Proxmox (OpenTofu)
  └── 4 VMs : master(10.0.20.10) + worker1/2/3(.11/.12/.13)
       └── K8s 1.30 (kubeadm, Cilium CNI, MetalLB BGP)
            ├── ArgoCD → gitops/apps/*.yml (soc-app-of-apps)
            │    ├── infra-metallb, infra-longhorn, infra-cert-manager, infra-ingress-nginx
            │    ├── infra-cortex, infra-thehive, infra-misp-redis, infra-shuffle
            │    └── soc-wazuh, soc-risk-engine, soc-monitoring, soc-eso, ...
            └── Ansible (day-1 only)
                 ├── Vault init/unseal + ESO bootstrap
                 ├── Secrets create-once (misp-redis, cortex-secret, thehive-secret)
                 ├── API post-config (TheHive custom fields, Cortex analyzers)
                 └── Shuffle workflows import + Wazuh webhook
```
