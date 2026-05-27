# SOC-as-code

> **Déploiement reproductible d'un Security Operations Center complet** sur Kubernetes bare-metal Proxmox, entièrement automatisé via Infrastructure as Code, Ansible et GitOps.
>
> Projet de fin d'études — soutenance juin 2026.

[![OpenTofu](https://img.shields.io/badge/OpenTofu-%E2%89%A51.6-blueviolet)](https://opentofu.org)
[![Ansible](https://img.shields.io/badge/Ansible-%E2%89%A52.15-red)](https://www.ansible.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.30-326CE5)](https://kubernetes.io)
[![ArgoCD](https://img.shields.io/badge/ArgoCD-GitOps-EF7B4D)](https://argo-cd.readthedocs.io)
[![Pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen)](https://pre-commit.com)

---

## Sommaire

- [Vue d'ensemble](#vue-densemble)
- [Architecture](#architecture)
- [Stack technique](#stack-technique)
- [Quickstart](#quickstart)
- [Structure du dépôt](#structure-du-dépôt)
- [Commandes principales](#commandes-principales)
- [Pipeline de déploiement](#pipeline-de-déploiement)
- [Pipeline SOC fonctionnel](#pipeline-soc-fonctionnel)
- [Tests et validation](#tests-et-validation)
- [Sécurité](#sécurité)
- [Troubleshooting](#troubleshooting)
- [Contributions](#contributions)
- [Licence et crédits](#licence-et-crédits)

---

## Vue d'ensemble

Ce dépôt assemble un SOC complet en une commande (`make deploy`). Toute la pile — du provisioning Proxmox jusqu'au selftest E2E qui rejoue 3 scénarios d'attaque — est **idempotente**, **versionnée** et **observable**.

**Objectifs du projet :**

1. Démontrer qu'un SOC opérationnel (détection, enrichissement, réponse) peut être livré « from scratch » avec les pratiques modernes (IaC, GitOps, Zero-Touch).
2. Maintenir un **pipeline E2E auto-vérifiable** : 3 scénarios (malware, brute-force, élévation de privilèges) sont rejoués à chaque selftest avec scoring naturel 50–100.
3. Fournir une base reproductible et défendable pour un mémoire.

**Métriques clés (dernier run réussi)**

| Métrique | Valeur |
|---|---|
| Durée `make deploy` from-scratch | ≈ 1h30 |
| Playbooks Ansible orchestrés | 28 |
| Applications ArgoCD gérées | 16 |
| Scénarios E2E validés | 3 / 3 PASS |
| Score SOC moyen (selftest) | 50–100 |

---

## Architecture

### Topologie réseau

```
                            ┌─────────────────────────┐
                            │   Proxmox VE (hyperv.)  │
                            └────────────┬────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
        Management 10.0.10.0/24    Core/K8s 10.0.20.0/24    MetalLB 10.0.30.50-80
       ┌──────────────┐         ┌──────────────────────┐    ┌─────────────────┐
       │  mgmt-soc    │         │  master  .10         │    │  Ingress 30.50  │
       │  10.0.10.10  │         │  worker1 .11         │    │  Wazuh   30.55  │
       │  (bastion)   │         │  worker2 .12         │    │  ArgoCD  30.56  │
       └──────────────┘         │  worker3 .13         │    └─────────────────┘
                                └──────────────────────┘
                                BGP peering ASN 65010 ↔ OPNsense ASN 65000
```

### Pile applicative

```
┌────────────────────────────────────────────────────────────────────┐
│                     Couche d'orchestration                         │
│  ArgoCD (GitOps)  ←  app-of-apps  ←  gitops/environments/lab       │
└────────────────────────────────────────────────────────────────────┘
        │
        ├─ Infra : MetalLB, ingress-nginx, cert-manager, Longhorn, ESO
        │
        ├─ Secrets : Vault 1.17 + External Secrets Operator → K8s Secrets
        │
        ├─ Observabilité : kube-prometheus-stack (Prometheus, Grafana)
        │
        └─ SOC :
              Wazuh → Shuffle SOAR → TheHive → Cortex → Risk Engine (Flask) → MISP
                │            │             │           │              │
                ▼            ▼             ▼           ▼              ▼
              Détection   Orchestration  Cases    Enrichissement  Threat Intel
                          (3 workflows :   IR      (MalwareBazaar, (feeds CIRCL,
                           malware, brute  Triage  CIRCL, Cortex   Botvrij,
                           force, privesc)         analyzers)      abuse.ch)
```

### Pipeline SOC d'une alerte

```
  ┌──────┐  syslog/agent   ┌──────────┐   webhook  ┌──────────┐
  │ Host │ ───────────────▶│  Wazuh   │ ──────────▶│ Shuffle  │
  └──────┘                 └──────────┘            └────┬─────┘
                                                        │ rule/event
                                                        ▼
                                            ┌──────────────────────┐
                                            │   Routing scenario   │
                                            │  malware/bruteforce/ │
                                            │  privesc / fallback  │
                                            └────────┬─────────────┘
                                                     │
                ┌────────────────────────────────────┼─────────────────────────┐
                ▼                                    ▼                         ▼
        ┌──────────────┐                  ┌────────────────────┐      ┌──────────────┐
        │ Cortex       │                  │ MISP (IOC lookup)  │      │  Risk Engine │
        │ (analyzers)  │                  │                    │      │   (Flask)    │
        └──────┬───────┘                  └─────────┬──────────┘      └──────┬───────┘
               │                                    │                        │
               └────────────────────────────────────┴────────────────────────┘
                                          │ score 0-100
                                          ▼
                                   ┌──────────────┐
                                   │   TheHive    │ ◀── case auto-créé
                                   └──────┬───────┘
                                          │ score ≥ 75
                                          ▼
                                  Active Response
                          (isolate-agent / disable-account)
                          ⚠ dry-run par défaut, whitelist hosts/users
```

---

## Stack technique

| Domaine | Outil | Version | Rôle |
|---|---|---|---|
| Hyperviseur | Proxmox VE | — | Fournit les VMs (master + workers) |
| IaC | OpenTofu | ≥ 1.6 | Provisioning Proxmox (provider `bpg/proxmox`) |
| Orchestration | Ansible | ≥ 2.15 | Configuration, déploiement, validation |
| Kubernetes | kubeadm | 1.30.4 | Cluster bare-metal |
| CNI | Cilium | 1.15.6 | VXLAN tunnel, Hubble UI, kube-proxy retained |
| Load Balancer | MetalLB | 0.14.9 | BGP ASN 65010 ↔ OPNsense ASN 65000 |
| Ingress | ingress-nginx | 4.11.x | + cert-manager (CA interne `soc-lab-ca-issuer`) |
| Stockage | Longhorn | 1.6.x | RWX pour Cortex, RWO pour le reste |
| GitOps | ArgoCD | 2.13.x | app-of-apps, ESO, infra et apps SOC |
| Secrets | Vault + ESO | 1.17 / 0.10 | Source de vérité des credentials |
| SIEM | Wazuh | 4.x | Détection, agents, decoders |
| SOAR | Shuffle | 1.4.x | 3 workflows scenario + fallback |
| Case management | TheHive | 5.x | Triage, customFields scoring |
| Analyzers | Cortex | 3.x | MalwareBazaar, CIRCL, Hash analyzers |
| Threat Intel | MISP | 2.4.x | Feeds CIRCL / Botvrij / abuse.ch |
| Custom | Risk Engine | Flask 2.4 | Scoring pondéré multi-source |
| Observabilité | kube-prometheus-stack | 60.x | Métriques cluster + apps |

---

## Quickstart

### Prérequis

- Bastion Linux avec accès root + clé SSH vers les workers
- Proxmox VE 8.x accessible en API
- Fichier `/etc/soc-as-code/.env` contenant les variables `TF_VAR_pm_*` (voir `docs/env.md`)

### Vérification

```bash
git clone <repo> && cd SOC-as-code
set -a; source /etc/soc-as-code/.env; set +a
make preflight        # vérifie binaires, accès Proxmox, collections Ansible
```

### Déploiement complet (~1h30)

```bash
make deploy           # alias de deploy-phased — progress live + ETA + récap
```

### Déploiement incrémental (cluster déjà provisionné)

```bash
make deploy DEPLOY_IAC=0      # skip Tofu apply + bootstrap K8s
```

### Validation E2E

```bash
make selftest         # rejoue malware + bruteforce + privesc
```

À la fin du `make deploy`, un banner ASCII liste les URLs :

```
ArgoCD   : https://argocd.apps.soc.lab
Wazuh    : https://wazuh.apps.soc.lab
TheHive  : https://thehive.apps.soc.lab
Cortex   : https://cortex.apps.soc.lab
MISP     : https://misp.apps.soc.lab
Shuffle  : https://shuffle.apps.soc.lab
```

---

## Structure du dépôt

```
SOC-as-code/
├── Makefile                  # Targets unitaires + help
├── Makefile.deploy.mk        # Orchestration complète make deploy
├── README.md                 # Ce fichier
├── SECURITY.md               # Modèle de menace, secrets, rotation
│
├── iac/                      # Infrastructure as Code (OpenTofu)
│   ├── main.tf               # Définition des VMs Proxmox
│   ├── provider.tf           # bpg/proxmox
│   ├── variables.tf
│   └── templates/            # cloud-init
│
├── ansible/                  # Configuration et déploiement
│   ├── ansible.cfg
│   ├── requirements.yml      # Collections : posix, general, crypto, k8s, hashi_vault
│   ├── inventories/
│   │   ├── k8s.ini           # Hosts master/workers
│   │   └── group_vars/all.yml
│   ├── playbooks/            # 00 → 210 (28 playbooks numérotés)
│   └── roles/                # 30+ rôles (vault, wazuh, shuffle, soc_*…)
│
├── gitops/                   # Manifests ArgoCD
│   ├── apps/                 # Applications ArgoCD
│   ├── base/                 # Manifests Kustomize de base
│   └── environments/lab/     # Surcharges environnement lab
│
├── scripts/                  # Helpers shell (preflight, wait, progress)
│   ├── preflight-check.sh
│   ├── phase-progress.sh     # Barre live + ETA depuis l'historique
│   ├── wait-argocd-synced.sh
│   └── wait-*.sh
│
├── .timings/                 # Historique des runs (TSV)
└── docs/                     # Docs spécifiques (redeploy, snippets)
```

---

## Commandes principales

```
make help                     # Liste de toutes les targets
make preflight                # Vérifier les prérequis
make deploy                   # Déploiement complet from-scratch
make deploy DEPLOY_IAC=0      # Skip IaC (cluster existant)
make deploy-raw               # Ancien comportement sans progress live
make deploy-timings           # Historique des durées
make destroy-lab CONFIRM=yes  # ⚠ Détruit le lab Proxmox

# Validation
make smoke                    # Smoke test cluster
make compliance               # Audit conformité (200)
make selftest                 # E2E selftest 3 scénarios (210)

# Lint
make lint                     # yamllint + ansible-lint + tflint
make pre-commit               # Hooks pre-commit sur tous les fichiers
```

Pour une cible individuelle, consulter `make help` ou les rôles Ansible dans `ansible/roles/`.

---

## Pipeline de déploiement

`make deploy` orchestre les playbooks dans cet ordre **strict** :

| Phase | Playbook | Rôle |
|---|---|---|
| 0  | `00-prereqs-install.yml` | Paquets système, kernel modules |
| 1  | `10-kube-binaries.yml`   | kubelet, kubeadm, kubectl, containerd |
| 2  | `20-control-plane.yml`   | `kubeadm init` master |
| 3  | `30-cni.yml`             | Cilium + Hubble |
| 4  | `40-join-workers.yml`    | Workers rejoignent le cluster |
| 5  | `50-post.yml`            | Post-install (labels, addons) |
| 6  | `60-post-config-master.yml` | cert-manager, Longhorn, ingress-nginx |
| 7  | `70-post-config-worker.yml` | Prérequis Longhorn sur workers |
| 8  | `75-vault.yml`           | Vault + External Secrets Operator |
| 9  | `76-monitoring.yml`      | kube-prometheus-stack |
| 10 | `77-argocd.yml`          | ArgoCD + app-of-apps |
| 11 | `80-databases.yml`       | PostgreSQL, Cassandra, Elasticsearch |
| 12 | `90-wazuh.yml`           | Wazuh manager + indexer + dashboard (parallèle) |
| 13 | `100-misp.yml`           | MISP + feeds CIRCL/Botvrij/abuse.ch (parallèle) |
| 14 | `110-cortex.yml`         | Cortex + analyzers (parallèle) |
| 15 | `120-thehive.yml`        | TheHive + customFields (parallèle) |
| 16 | `130-soc-config.yml`     | Configuration croisée Wazuh ↔ Shuffle |
| 17 | `140-soc-smoke.yml`      | Smoke tests SOC |
| 18 | `150-soc-netpol.yml`     | NetworkPolicies |
| 19 | `170-soc-foundations.yml` | RBAC + ServiceAccounts |
| 20 | `180-soc-automation.yml` | Workflows Shuffle (1ʳᵉ passe) |
| 21 | `185-shuffle.yml`        | Déploie Shuffle SOAR |
| 22 | `180-soc-automation.yml` | (2ᵉ passe — dépendance circulaire connue) |
| 23 | `190-soc-risk-engine.yml` | Risk Engine Flask v2.4 |
| 24 | `200-soc-compliance.yml` | Audit conformité |
| 25 | `210-soc-selftest.yml`   | Selftest E2E 3 scénarios |

**Parallélisation :** étapes 12–15 (Wazuh, MISP, Cortex, TheHive) tournent en `-j4` une fois les bases prêtes. Vault et Monitoring se déploient en parallèle pendant la phase ArgoCD.

---

## Pipeline SOC fonctionnel

Une fois déployé, le SOC réagit aux alertes selon la règle Wazuh déclenchée :

| Rules Wazuh | Scenario | Cortex | MISP | Risk multiplier | AR command |
|---|---|---|---|---|---|
| 100200-100202 | **malware** | MalwareBazaar / CIRCL Hash | Hash IOC | × 1.3 | isolate-agent |
| 5712 / 60122 / 92657 | **bruteforce** | MaxMind GeoIP | IP IOC | × 0.9 | firewall-drop |
| 5402 / 5403 / 4672 | **privesc** | Enrich Wazuh agent | — | × 1.5 | disable-account |
| Autres rules | **fallback** | analyzers généraux | — | × 1.0 | — |

**Seuils de décision** (`ansible/inventories/group_vars/all.yml`) :

| Score | Décision | Action |
|---|---|---|
| < 15 | auto_close | Aucune action, alerte fermée |
| 15–49 | reviewed | Case TheHive en attente d'analyse |
| 50–74 | auto_promote | Case promu, notification analyste |
| 75–89 | auto_contain | Active Response (dry-run par défaut) |
| ≥ 90 | escalate | Active Response + escalade |

---

## Tests et validation

```bash
make lint              # Tous les linters (YAML, Ansible, Terraform)
make smoke             # Cluster K8s opérationnel
make compliance        # Audit Phase 7 (markers, ConfigMaps, AR scripts)
make selftest          # E2E 3 scénarios (malware/bruteforce/privesc)
```

**KPIs collectés par le selftest** (`ansible/roles/soc_selftest/`)

- **MTTD** (Mean Time To Detect)
- **MTTI** (Mean Time To Investigate)
- **MTTC** (Mean Time To Contain)
- **MTTR** (Mean Time To Resolve)
- Latences par étape : Wazuh → Shuffle → Cortex → Risk Engine → TheHive

---

## Sécurité

Voir [SECURITY.md](./SECURITY.md) pour le modèle de menace complet, la rotation des secrets et la liste des ports exposés.

**Garde-fous en place :**

- Tous les secrets transitent par Vault + External Secrets Operator.
- `gitleaks` en pre-commit + `check-added-large-files` + `detect-private-key`.
- Active Response en **dry-run par défaut** (`SOC_AR_DRY_RUN=1`) avec whitelist hosts/users.
- NetworkPolicies par défaut deny-all sur les namespaces SOC.
- mTLS interne via cert-manager (CA `soc-lab-ca-issuer`).
- Création des Secrets K8s en pattern **create-once** (jamais d'overwrite).
- `no_log: true` sur toutes les tâches manipulant des credentials.

---

## Troubleshooting

### Pièges connus du pipeline

| Symptôme | Cause | Remède |
|---|---|---|
| `180-soc-automation` échoue : `soc-shuffle-webhook-config` absent | Dépendance circulaire 180→185→180 | Laisser le 2ᵉ passage automatique (orchestré par Makefile) |
| Pod Wazuh sans intégration Shuffle après reboot | Fichiers éphémères dans le pod | `make automation` (rejoue 180 --tags integration) |
| ArgoCD `soc-eso-externalsecrets` reste `Degraded` | 2/16 ExternalSecrets attendent les ServiceAccounts | Normal jusqu'à 170-foundations, géré par `--allow-degraded` |
| Risk score = 0 ou -1 dans le selftest | Shuffle n'a pas appelé le risk-engine | Vérifier `webhook_urls` dans `soc-shuffle-webhook-config` |
| `make deploy` échoue à `iac-apply` | Crédentials Proxmox absents | `source /etc/soc-as-code/.env` |
| MISP startup probe timeout | Init MISP 7–12 min normal | `progressDeadline: 1800s` configuré |
| TheHive renvoie `"OK"` au lieu de JSON | Query POST sans résultat (TheHive 5) | Vérifier `type_debug == 'list'` avant traitement |

### Pour aller plus loin

- `docs/redeploy-procedure.md` — procédure de re-déploiement
- `.timings/deploy-phased-*.log` — historique des runs (durée par phase)

---

## Contributions

Hooks pre-commit obligatoires :

```bash
make pre-commit-install
make pre-commit            # Lance tous les hooks sur tous les fichiers
```

Conventions de commit :

```
feat(<scope>): <description>
fix(<scope>): <description>
docs: <description>
chore(<scope>): <description>
```

Scopes courants : `iac`, `wazuh`, `shuffle`, `cortex`, `thehive`, `misp`, `risk-engine`, `selftest`, `gitops`, `vault`, `argocd`.

---

## Licence et crédits

**Auteur** — Thomas (mémoire de fin d'études)
**Date de soutenance** — juin 2026
**Encadrement** — voir le mémoire

**Outils et projets open source utilisés** : Kubernetes, OpenTofu, Ansible, ArgoCD, HashiCorp Vault, External Secrets Operator, Wazuh, MISP, TheHive, Cortex, Shuffle, MetalLB, Cilium, Longhorn, cert-manager, ingress-nginx, kube-prometheus-stack.

Voir les LICENSE individuelles de chaque composant.
