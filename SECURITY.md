# Security Policy — SOC-as-code

Ce document décrit le **modèle de menace**, la **gestion des secrets**, les **ports exposés** et la **procédure de rotation** pour le projet SOC-as-code.

Projet de fin d'études — environnement de laboratoire pédagogique. **Non destiné à la production sans durcissement supplémentaire** (voir [Limitations connues](#limitations-connues)).

---

## Sommaire

- [Modèle de menace](#modèle-de-menace)
- [Gestion des secrets](#gestion-des-secrets)
- [Surface réseau exposée](#surface-réseau-exposée)
- [Rotation des credentials](#rotation-des-credentials)
- [Garde-fous Active Response](#garde-fous-active-response)
- [Détection & scans](#détection--scans)
- [Limitations connues](#limitations-connues)
- [Reporting d'une vulnérabilité](#reporting-dune-vulnérabilité)

---

## Modèle de menace

### Périmètre protégé

- VMs Proxmox (master + workers Kubernetes) sur le sous-réseau `10.0.20.0/24`.
- Bastion `mgmt-soc` (`10.0.10.10`) qui héberge Ansible, OpenTofu et le kubeconfig.
- Stack SOC en namespaces dédiés (`soc-wazuh`, `soc-core`, `soc-cortex`, `soc-thehive`, `soc-shuffle`, `soc-vault`).
- Secrets dans Vault (KV v2) répliqués vers Kubernetes via External Secrets Operator.

### Acteurs / Adversaires considérés

| Acteur | Capacités supposées | Mitigation principale |
|---|---|---|
| Attaquant externe (Internet) | Scan ports, exploitation services | LB MetalLB ne route que `apps.soc.lab` derrière Ingress NGINX TLS |
| Attaquant interne (VLAN core) | Latéralisation via service mesh | NetworkPolicies deny-all par défaut + mTLS interne |
| Compromission d'un agent Wazuh | Push d'évents malicieux | Decoders / rules signés, Active Response whitelist + dry-run |
| Erreur humaine (opérateur) | Mauvais commit, fuite de secret | `gitleaks` en pre-commit, `.gitignore` strict, secrets create-once |
| Compromission de l'hyperviseur Proxmox | Accès root à toutes les VMs | Hors scope — segmentation physique + accès console limité |

### Hors périmètre

- Sécurité physique du serveur Proxmox.
- Protection DDoS au niveau réseau (responsabilité du firewall périmétrique OPNsense).
- Conformité réglementaire (RGPD, ISO 27001) : projet à vocation pédagogique.

---

## Gestion des secrets

### Source de vérité : HashiCorp Vault

Vault 1.17 est déployé dans `soc-vault` avec storage Raft (Longhorn). C'est la **source unique** des credentials.

```
KV v2 mounts :
  secret/
    bootstrap/          # Mots de passe initiaux (déployés au premier run)
    service-accounts/   # SA tokens consommés par 170-soc-foundations
    integrations/       # API keys Shuffle, Cortex, MISP, TheHive
    tls/                # Backup des cert-manager certificates
```

### Réplication vers Kubernetes

External Secrets Operator (ESO 0.10.x) synchronise Vault → K8s Secrets via `ExternalSecret` CRD. Refresh interval : 1 heure.

Aucun secret n'est jamais écrit en clair dans :

- les manifestes ArgoCD (`gitops/`)
- les playbooks Ansible (variables sensibles obligatoirement chargées via `community.hashi_vault`)
- les ConfigMaps Kubernetes
- les logs Ansible (`no_log: true` obligatoire sur les tâches manipulant des credentials)

### Crédentials Proxmox (bootstrap)

Le fichier `/etc/soc-as-code/.env` contient les variables `TF_VAR_pm_api_token`, `TF_VAR_pm_user`, etc. nécessaires au tout premier `tofu apply` (Vault n'existe pas encore).

**Permissions requises :**

```bash
chmod 600 /etc/soc-as-code/.env
chown root:root /etc/soc-as-code/.env
```

> **Amélioration prévue (post-soutenance)** : externalisation via `pass` ou `age` pour ne plus stocker les credentials en clair sur le bastion.

### Pattern create-once

Les Secrets Kubernetes sensibles (mots de passe d'admin, API keys) sont créés **une seule fois** par Ansible :

```yaml
- name: Check if secret already exists
  k8s_info:
    api_version: v1
    kind: Secret
    name: <secret-name>
  register: existing_secret

- name: Create secret only if absent
  k8s:
    state: present
    definition: { ... }
  when: existing_secret.resources | length == 0
  no_log: true
```

**Conséquence** : un `make deploy` répété ne réécrase **jamais** un secret existant. La rotation se fait explicitement (voir section dédiée).

---

## Surface réseau exposée

### Services accessibles via Ingress NGINX (LB `10.0.30.50`)

| Service | URL | Port | TLS | Auth |
|---|---|---|---|---|
| ArgoCD | `https://argocd.apps.soc.lab` | 443 | cert-manager interne | admin + Vault |
| Wazuh Dashboard | `https://wazuh.apps.soc.lab` | 443 | cert-manager interne | LDAP/admin |
| TheHive | `https://thehive.apps.soc.lab` | 443 | cert-manager interne | local users |
| Cortex | `https://cortex.apps.soc.lab` | 443 | cert-manager interne | local users |
| MISP | `https://misp.apps.soc.lab` | 443 | cert-manager interne | local users |
| Shuffle | `https://shuffle.apps.soc.lab` | 443 | cert-manager interne | local users |
| Grafana | `https://grafana.apps.soc.lab` | 443 | cert-manager interne | admin + Vault |

### Services exposés directement (LB dédiés)

| Service | IP LB | Ports | Usage |
|---|---|---|---|
| Wazuh agents | `10.0.30.55` | 1514/TCP, 1515/TCP | Enrôlement + flux d'événements |

### Ports cluster internes (jamais exposés au LAN)

- Kubernetes API : 6443 (master uniquement, accès via bastion)
- ETCD : 2379-2380 (cluster interne)
- Kubelet : 10250 (cluster interne)
- Vault : 8200 (ClusterIP, jamais Ingress)

### NetworkPolicies (`150-soc-netpol.yml`)

Politique par défaut : **deny-all** sur tous les namespaces `soc-*`. Les flux autorisés sont :

- Wazuh agents → manager (1514/1515)
- Shuffle → Wazuh / TheHive / Cortex / MISP / Risk Engine (API REST)
- TheHive → Cortex (API + responder callbacks)
- Cortex → analyzers externes (MalwareBazaar, CIRCL, MaxMind) en egress
- MISP → feeds externes (CIRCL, Botvrij, abuse.ch) en egress
- Prometheus → tous les `/metrics` endpoints (scrape)

---

## Rotation des credentials

### Mot de passe admin ArgoCD

Le bootstrap utilise `argocd_admin_password_bootstrap` (`group_vars/all.yml`). Une fois Vault disponible, le mot de passe est remplacé par celui issu de Vault :

```bash
make argocd-update-password
```

### API keys Shuffle / Cortex / MISP / TheHive

Régénérées via les UI respectives, puis stockées dans Vault :

```bash
vault kv put secret/integrations/shuffle apikey=<nouvelle-cle>
# ESO synchronise automatiquement (jusqu'à 1h) ou forcer :
kubectl -n soc-shuffle annotate externalsecret <name> force-sync=$(date +%s) --overwrite
```

### Certificats TLS (cert-manager)

Les certificats internes sont émis par le ClusterIssuer `soc-lab-ca-issuer` avec une durée de validité **90 jours** et un renouvellement automatique **30 jours** avant expiration.

Le CA racine `soc-lab-ca` a une durée de **10 ans** (généré au premier `60-post-config-master.yml`). Sa rotation nécessite une re-émission de tous les certs enfants.

```bash
# Vérifier l'expiration du CA
kubectl -n cert-manager get secret soc-lab-ca-key-pair -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -enddate -noout
```

### Tokens Vault

Le token root Vault est **scellé** (sealed) automatiquement après le bootstrap. Les playbooks utilisent un token applicatif via `community.hashi_vault`.

> **Important** : ne jamais committer `vault-root-token` ou `vault-unseal-keys` — exclus par `.gitignore`.

### Mots de passe utilisateurs (TheHive / Cortex / MISP / Wazuh)

Création initiale via bootstrap Ansible, puis rotation manuelle par les utilisateurs via leur UI. Les comptes de service (`thehive_bootstrap_user`, `wazuh_admin`) sont rotables via :

```bash
ansible-playbook ansible/playbooks/120-thehive.yml --tags bootstrap -e rotate_password=true
```

---

## Garde-fous Active Response

L'Active Response (AR) est la partie la plus sensible du SOC : elle peut **isoler un host** ou **désactiver un compte**.

### Double garde-fou

1. **Côté Shuffle** : l'AR n'est invoqué que si `risk_decision in [contained, escalated]` (score ≥ 75).
2. **Côté script in-pod** : `/var/ossec/active-response/bin/isolate-agent.sh` et `disable-account.sh` vérifient :
   - Variable `SOC_AR_DRY_RUN` (par défaut `1` = log-only, pas d'action réelle)
   - Whitelist hosts : `/var/ossec/etc/lists/ar-whitelist-hosts.txt`
   - Whitelist users : `/var/ossec/etc/lists/ar-whitelist-users.txt` (par défaut : `root, admin, soc-ops, ansible, wazuh`)

### Passage en mode actif (production réelle)

```yaml
# envs/prod.yml ou inventory variable
soc_automation_ar_dry_run: false
```

**Procédure obligatoire avant bascule :**

1. Vérifier que la whitelist `ar-whitelist-hosts.txt` contient tous les serveurs critiques (DC, monitoring, jump hosts).
2. Vérifier que `ar-whitelist-users.txt` contient tous les comptes humains et de service critiques.
3. Tester d'abord en environnement de dev avec une whitelist large.
4. Auditer les logs `/var/ossec/logs/active-responses.log` après chaque alerte.

> **Risque** : passer `soc_automation_ar_dry_run: false` SANS remplir la whitelist = risque réel de couper un host de production ou de verrouiller un compte légitime.

---

## Détection & scans

### Pre-commit hooks (locaux)

Configuration dans `.pre-commit-config.yaml` :

- **gitleaks v8.21** — détection de secrets dans le diff
- **detect-private-key** — détection de clés privées commitées
- **check-added-large-files** (maxkb=500) — bloque les binaires
- **yamllint** + **ansible-lint --profile=production**
- **terraform_validate** + **terraform_tflint** + **terraform_fmt**

Installation obligatoire :

```bash
make pre-commit-install
```

### Validation CI (GitHub Actions)

Workflows dans `.github/workflows/` :

- `validate.yml` — `tofu validate`, `ansible-playbook --syntax-check`
- `validate-ansible.yml` — `ansible-lint` complet
- `argocd-validate.yml` — `kubectl --dry-run` sur les manifestes GitOps

> **Amélioration prévue** : ajout d'un job `secrets-scan.yml` avec `gitleaks` en CI (aujourd'hui uniquement local).

### Audit de conformité

Lancé automatiquement par `make deploy` (étape 24) et exécutable à la demande :

```bash
make compliance      # Audit Phase 7 : markers, ConfigMaps, AR scripts
```

Vérifications :

- Marker `soc-shuffle-marker-workflows` à jour (composite hash des 3 scénarios)
- ConfigMap `soc-shuffle-webhook-config` contient `webhook_urls` non vide
- Nombre de blocs `<integration>` dans `ossec.conf` (N+1 attendu)
- Scripts AR présents in-pod Wazuh
- `soc-ar.env` configuré
- Risk Engine `policy_version=2.4`

### Selftest E2E

```bash
make selftest        # Rejoue malware + bruteforce + privesc
```

Vérifie le pipeline complet : Wazuh → Shuffle → Cortex/MISP → Risk Engine → TheHive + AR dry-run.

---

## Limitations connues

### Non couvert (à intégrer pour usage production)

| Aspect | État actuel | Amélioration recommandée |
|---|---|---|
| Crédentials Proxmox bootstrap | `.env` en clair (chmod 600) | Externaliser via `pass` / `age` / KMS cloud |
| Signature d'images container | Non vérifiée | Mettre en place Cosign + admission policy |
| Politique d'admission | Aucune | Kyverno ou OPA Gatekeeper (no `:latest`, requests/limits requis) |
| Scan d'images container | Non automatisé | Trivy en CI sur les images custom (risk-engine) |
| SBOM | Non généré | Syft sur les builds risk-engine |
| Audit logs cluster | Non centralisé | Stream vers Wazuh ou Loki |
| Backup / DR | Manuel | Velero + snapshots Longhorn + snapshots Proxmox |
| Tests de résilience | Aucun | Litmus / Chaos Mesh |
| Authentification SSO | Non | OIDC via Keycloak ou équivalent |
| Hardening OS workers | Default Ubuntu 24.04 | CIS Benchmark, AppArmor profiles, auditd |

### Notes opérationnelles

- Le mot de passe `argocd_admin_password_bootstrap` dans `group_vars/all.yml` est **public** (visible dans le repo). C'est un mot de passe temporaire valide uniquement entre le premier `make argocd` et le `make argocd-update-password`. Il **doit** être remplacé immédiatement après bootstrap.
- Les tokens Wazuh API et les password Vault sont stockés dans `ansible/.secrets/` (exclu Git). Leur rotation est manuelle et non orchestrée.
- En cas de perte des unseal keys Vault, **tous les secrets stockés sont perdus** — backup obligatoire hors cluster.

---

## Reporting d'une vulnérabilité

Ce projet est un travail académique. Si vous identifiez une vulnérabilité :

- **Ne pas** ouvrir d'issue publique avec les détails de l'exploitation.
- Contacter directement l'auteur (voir contact dans le mémoire).
- Documenter : version affectée, vecteur d'attaque, PoC si possible.

Réponse attendue sous **7 jours**.
