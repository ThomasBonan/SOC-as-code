# tls_reloader

Sidecar générique qui surveille la rotation de certificats (cert-manager) et
déclenche un reload à chaud du workload sans restart du pod.

## Pourquoi

Quand cert-manager renouvelle un `Certificate`, le Secret est mis à jour et
Kubernetes propage les nouveaux fichiers dans les pods via le volume projeté.
**Mais la plupart des workloads qui terminent du TLS directement
(Vault, OpenSearch/Wazuh, etc.) chargent les certs en mémoire au démarrage**
et ne les rechargent pas automatiquement — le pod continue donc de servir
l'ancien cert jusqu'à restart. Résultat : intervention manuelle à chaque
rotation.

Ce rôle déploie un sidecar minimal (polling md5 des fichiers montés) qui
détecte la rotation et exécute une commande de reload spécifique au
workload :

| Workload | Mécanisme de reload | Downtime |
|---|---|---|
| Vault  | `kill -HUP $(pidof vault)` (shareProcessNamespace) | zéro |
| OpenSearch / Wazuh Indexer | `PUT /_plugins/_security/api/ssl/{http,transport}/reloadcerts` | zéro |
| Wazuh Manager | `kubectl exec ... /var/ossec/bin/wazuh-control restart` | ~15s |

## Modes

- `configmap_only` : crée seulement le `ConfigMap` portant le script
  `tls-reloader.sh`. À utiliser quand le chart Helm cible supporte déjà
  `extraContainers` (ex. `hashicorp/vault`) — le sidecar est déclaré
  dans les values et monte le ConfigMap.
- `patch_sts` : applique un `kubectl patch --type=strategic` sur le
  StatefulSet cible pour y injecter le sidecar + `shareProcessNamespace` +
  le volume ConfigMap. À rejouer après chaque `helm upgrade` qui écrase
  la spec (idempotent).

## Variables principales

Voir `defaults/main.yml` pour la liste complète.

```yaml
tls_reloader_namespace: "soc-vault"
tls_reloader_watch_files:
  - /vault/tls/tls.crt
  - /vault/tls/tls.key
  - /vault/tls/ca.crt
tls_reloader_reload_cmd: "kill -HUP $(pidof vault)"
tls_reloader_share_process_namespace: true
tls_reloader_mode: "configmap_only"   # ou patch_sts
```

## Exemples d'utilisation

### Vault (configmap_only + Helm values)

```yaml
# playbook
- include_role:
    name: tls_reloader
  vars:
    tls_reloader_namespace: "{{ vault_namespace }}"
    tls_reloader_mode: configmap_only
    tls_reloader_watch_files:
      - /vault/tls/tls.crt
      - /vault/tls/tls.key
      - /vault/tls/ca.crt
    tls_reloader_reload_cmd: "kill -HUP $(pidof vault)"
    tls_reloader_share_process_namespace: true
```

Et dans `vault-values.yml.j2` (chart hashicorp/vault) :

```yaml
server:
  shareProcessNamespace: true
  volumes:
    - name: tls-reloader-script
      configMap:
        name: "{{ tls_reloader_configmap_name | default('tls-reloader-script') }}"
        defaultMode: 0755
  extraContainers:
    - name: tls-reloader
      image: docker.io/busybox:1.36
      command: ["/bin/sh", "/scripts/tls-reloader.sh"]
      env:
        - name: WATCH_FILES
          value: "/vault/tls/tls.crt /vault/tls/tls.key /vault/tls/ca.crt"
        - name: RELOAD_CMD
          value: "kill -HUP $(pidof vault)"
      volumeMounts:
        - name: tls-reloader-script
          mountPath: /scripts
          readOnly: true
        - name: vault-tls
          mountPath: /vault/tls
          readOnly: true
```

### Wazuh Indexer (patch_sts + API reload)

```yaml
- include_role:
    name: tls_reloader
  vars:
    tls_reloader_namespace: "{{ wazuh_namespace }}"
    tls_reloader_mode: patch_sts
    tls_reloader_workload_kind: StatefulSet
    tls_reloader_workload_name: wazuh-indexer
    tls_reloader_sidecar_image: "docker.io/curlimages/curl:8.6.0"
    tls_reloader_watch_files:
      - /certs/node.pem
      - /certs/node-key.pem
      - /certs/root-ca.pem
    tls_reloader_reload_cmd: |
      curl -sk --cert /admin-certs/admin.pem --key /admin-certs/admin-key.pem -X PUT https://localhost:9200/_plugins/_security/api/ssl/http/reloadcerts &&
      curl -sk --cert /admin-certs/admin.pem --key /admin-certs/admin-key.pem -X PUT https://localhost:9200/_plugins/_security/api/ssl/transport/reloadcerts
    tls_reloader_extra_volume_mounts:
      - { name: node-certs,  mountPath: /certs,       readOnly: true }
      - { name: admin-certs, mountPath: /admin-certs, readOnly: true }
```
