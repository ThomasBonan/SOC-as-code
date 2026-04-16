# GitOps — SOC-as-code

Ce répertoire contient les manifests ArgoCD pour la gestion GitOps du SOC.

## Structure

```
gitops/
  apps/                        # Définitions des Applications ArgoCD
    argocd-self.yml            # Auto-gestion ArgoCD (self-management)
    soc-infra.yml              # ApplicationSet infrastructure (cert-manager, ingress, metallb, longhorn)
    soc-security.yml           # ApplicationSet sécurité (vault, eso)
    soc-monitoring.yml         # Application monitoring (kube-prometheus-stack, loki, blackbox)
    soc-apps.yml               # ApplicationSet apps SOC (wazuh, misp, cortex, thehive, shuffle, risk-engine)
  environments/
    lab/                       # Valeurs spécifiques à l'environnement lab
      values-common.yml        # Valeurs communes (replicas: 1, domaine, ressources minimales)
  base/
    argocd/
      kustomization.yaml       # Kustomize overlay pour la configuration ArgoCD elle-même
```

## Conventions

- **prune: false** sur toutes les Applications — ne pas supprimer automatiquement de ressources
- **selfHeal: true** — revenir à l'état Git si modifié manuellement
- **ServerSideApply: true** — éviter les conflits de field manager avec les ressources existantes
- **CreateNamespace: true** — créer les namespaces manquants

## Ajouter une nouvelle application

1. Créer le répertoire `gitops/environments/lab/<app-name>/`
2. Ajouter un fichier `values.yaml` (apps Helm) ou des manifests YAML + `kustomization.yaml` (apps raw)
3. L'ApplicationSet `soc-apps.yml` détectera automatiquement le nouveau répertoire

## Bootstrap

ArgoCD est déployé par Ansible (`ansible/playbooks/77-argocd.yml`).
Une fois déployé, il peut se gérer lui-même via `gitops/base/argocd/`.

## Variables requises

- `argocd_repo_url` : URL du repo Git (à définir dans `group_vars/all.yml`)
- `argocd_repo_target_revision` : branche cible (défaut: `main`)
