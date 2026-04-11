# SOCOM GMAO — Guide de déploiement Web v2

## Structure des fichiers

```
gmao/
├── gmao_server_v2.py      ← Serveur Flask (REMPLACE gmao_server.py)
├── gmao_web_pc.html       ← Interface PC (online uniquement)
├── gmao_mobile_v2.html    ← Interface Mobile PWA (online + offline)
├── sw.js                  ← Service Worker (obligatoire pour offline)
├── gmao_shared.db         ← Votre base SQLite existante
└── gmao_sync.py           ← Synchronisation PC→Cloud (inchangé)
```

---

## Option A — PythonAnywhere (le plus simple)

### 1. Uploader les fichiers
Dans la console Files de PythonAnywhere, uploader dans `/home/[username]/gmao/` :
- `gmao_server_v2.py`
- `gmao_web_pc.html`
- `gmao_mobile_v2.html`
- `sw.js`

### 2. Configurer le WSGI
Onglet **Web** > votre app > cliquer sur le lien WSGI file.
Remplacer le contenu par :
```python
import sys
sys.path.insert(0, '/home/[username]/gmao')
from gmao_server_v2 import app as application
```

### 3. Reload
Cliquer **Reload** dans l'onglet Web.

### URLs
- **PC** : `https://[username].pythonanywhere.com/pc`
- **Mobile** : `https://[username].pythonanywhere.com/`
- **Auto-detect** : `https://[username].pythonanywhere.com/` (redirige selon User-Agent)

---

## Option B — VPS recommandé (OVH / Hostinger ~5€/mois)

### 1. Installation
```bash
sudo apt update && sudo apt install python3-pip nginx -y
pip3 install flask flask-cors gunicorn

# Créer le dossier
mkdir -p /var/www/gmao
# Copier vos fichiers dans /var/www/gmao/
```

### 2. Lancer avec Gunicorn
```bash
cd /var/www/gmao
gunicorn -w 2 -b 127.0.0.1:8000 gmao_server_v2:app --daemon --log-file=/var/log/gmao.log
```

### 3. Service systemd (démarrage automatique)
```ini
# /etc/systemd/system/gmao.service
[Unit]
Description=SOCOM GMAO
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/gmao
ExecStart=/usr/local/bin/gunicorn -w 2 -b 127.0.0.1:8000 gmao_server_v2:app
Restart=always

[Install]
WantedBy=multi-user.target
```
```bash
systemctl enable gmao && systemctl start gmao
```

### 4. Nginx (reverse proxy + HTTPS)
```nginx
# /etc/nginx/sites-available/gmao
server {
    listen 80;
    server_name votre-domaine.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name votre-domaine.com;

    ssl_certificate     /etc/letsencrypt/live/votre-domaine.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/votre-domaine.com/privkey.pem;

    # Service Worker doit être servi sans cache
    location /sw.js {
        proxy_pass http://127.0.0.1:8000;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Service-Worker-Allowed "/";
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 50M;
    }
}
```
```bash
ln -s /etc/nginx/sites-available/gmao /etc/nginx/sites-enabled/
certbot --nginx -d votre-domaine.com
nginx -t && systemctl reload nginx
```

---

## Accès

| URL | Interface |
|-----|-----------|
| `https://votre-domaine.com/` | Auto (PC si bureau, Mobile si smartphone) |
| `https://votre-domaine.com/pc` | Forcer interface PC |
| `https://votre-domaine.com/?v=mobile` | Forcer interface mobile |
| `https://votre-domaine.com/api/health` | Vérification serveur |

---

## Installer la PWA Mobile sur smartphone

1. Ouvrir `https://votre-domaine.com/` sur le smartphone
2. Sur **iPhone** : Safari > bouton Partager > "Sur l'écran d'accueil"
3. Sur **Android** : Chrome > menu ⋮ > "Ajouter à l'écran d'accueil"
4. L'icône GMAO apparaît comme une app native
5. Elle fonctionne **hors ligne** après la première ouverture

---

## Synchronisation PC → Cloud

Inchangé — utiliser `gmao_sync.py` comme avant :
```
python gmao_sync.py
```

---

## Variables d'environnement (optionnel)

```bash
export GMAO_DB=/chemin/vers/gmao_shared.db
export GMAO_SYNC_SECRET=VotreSecretPerso
```

---

## Fonctionnalités offline (Mobile PWA)

| Fonctionnalité | Online | Offline |
|----------------|--------|---------|
| Connexion | ✅ | ✅ (session sauvegardée) |
| Voir BT | ✅ | ✅ (cache IndexedDB) |
| Créer BT | ✅ | ✅ (file d'attente) |
| Mettre à jour statut | ✅ | ✅ (file d'attente) |
| Voir planning | ✅ | ✅ (cache) |
| Créer CR | ✅ | ✅ (file d'attente) |
| Sync automatique | — | ✅ (au retour réseau) |
