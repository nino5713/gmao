# GMAO SOCOM — Guide de déploiement du patch v3.2

## ⚡ TL;DR (déploiement en 3 minutes)

```bash
ssh root@187.127.68.131
cd /var/www/gmao

# 1. Backup avant changement
cp app.py app.py.bak-v3.1
sqlite3 gmao.db ".backup gmao-pre-v3.2.db" 2>/dev/null || \
  python3 -c "import sqlite3; src=sqlite3.connect('gmao.db'); dst=sqlite3.connect('gmao-pre-v3.2.db'); src.backup(dst)"

# 2. Télécharger le nouveau app.py (après push sur GitHub)
wget -O app.py https://raw.githubusercontent.com/nino5713/gmao/main/app.py

# 3. Installer les nouvelles dépendances
/var/www/gmao/venv/bin/pip install bcrypt flask-limiter

# 4. Définir la variable CORS (IMPORTANT en prod)
# Éditer /etc/systemd/system/gmao.service (voir plus bas)

# 5. Redémarrer
systemctl daemon-reload
systemctl restart gmao
journalctl -u gmao -n 30 --no-pager
```

## 📋 Ce qui change

### Côté serveur
- ✅ **Hashing bcrypt** (avec migration transparente des anciens hash SHA-256 au login)
- ✅ **Token signé HMAC** avec expiration configurable (défaut 7 jours)
- ✅ **Révocation de sessions** automatique au changement de mot de passe
- ✅ **CORS restreint** via variable d'environnement `GMAO_CORS_ORIGINS`
- ✅ **Rate limiting** : 10 login/min, 5 reset-password/h (par IP)
- ✅ **Limite payload** : 10 Mo (protection contre DoS sur upload logo)
- ✅ **Logging structuré** avec rotation : `/var/www/gmao/logs/gmao.log` (5 × 5 Mo)
- ✅ **Migrations DB** centralisées dans `init_db()` (plus d'ALTER TABLE éparpillés)
- ✅ **Connexions DB** gérées proprement (teardown_appcontext)
- ✅ **Nettoyage** de la table orpheline `utilisateurs_new`
- ✅ **Longueur MDP minimum** : 8 caractères (au lieu de 6)

### Compatibilité
- ✅ **Tokens existants continuent de fonctionner** : le code accepte l'ancien format `uid:hash` pour la transition
- ✅ **Mots de passe existants continuent de fonctionner** : SHA-256 legacy vérifié et migré vers bcrypt au prochain login
- ⚠️ **Les sessions actives ne sont PAS invalidées** au déploiement (transparent pour les utilisateurs)
- ⚠️ Quand un utilisateur change son mot de passe, ses autres sessions sont invalidées (sécurité)

## 🔧 Configuration systemd

Édite `/etc/systemd/system/gmao.service` et ajoute les variables d'environnement :

```ini
[Unit]
Description=GMAO SOCOM
After=network.target

[Service]
WorkingDirectory=/var/www/gmao
ExecStart=/var/www/gmao/venv/bin/gunicorn -w 2 -b 127.0.0.1:8000 app:app --timeout 120
Restart=always
User=www-data
Group=www-data

# --- IMPORTANT : configuration sécurité ---
Environment="GMAO_CORS_ORIGINS=https://ton-domaine.lu,http://187.127.68.131"
Environment="GMAO_TOKEN_TTL=604800"

[Install]
WantedBy=multi-user.target
```

Puis :
```bash
systemctl daemon-reload
systemctl restart gmao
```

**Valeurs à définir pour `GMAO_CORS_ORIGINS`** :
- En dev : `http://localhost:5173,http://localhost:8000`
- En prod avec IP seule : `http://187.127.68.131`
- En prod avec domaine HTTPS : `https://gmao.tondomaine.lu` (après activation du domaine)

## 🧪 Vérifications après déploiement

```bash
# 1. Service actif ?
systemctl status gmao

# 2. Logs sans erreur ?
tail -f /var/www/gmao/logs/gmao.log

# 3. Test de connexion
curl -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@gmao.fr","password":"TON_MDP"}'
# Doit renvoyer un token au format uid.iat.tv.sig (4 segments séparés par .)

# 4. Vérifier la présence des nouvelles colonnes
sqlite3 /var/www/gmao/gmao.db "PRAGMA table_info(utilisateurs);"
# Doit contenir token_version, reset_token, reset_expires

# 5. Vérifier que le secret serveur est créé
sqlite3 /var/www/gmao/gmao.db "SELECT cle FROM parametres_app WHERE cle='server_secret';"
# Doit renvoyer 'server_secret'
```

## 🔄 Rollback si problème

```bash
cd /var/www/gmao
cp app.py.bak-v3.1 app.py

# Restaurer la DB seulement si nécessaire (les migrations ajoutent des colonnes — rétrocompatibles)
# En cas de gros problème :
# cp gmao-pre-v3.2.db gmao.db

systemctl restart gmao
```

## ⚠️ Actions post-déploiement recommandées

1. **Changer les mots de passe triviaux** (point 1 de l'audit — à faire manuellement via l'interface ou un script SQL)
2. **Définir `GMAO_CORS_ORIGINS`** dans systemd dès que le domaine est actif
3. **Surveiller les logs** pendant 24h : `journalctl -u gmao -f`
4. **Tester un reset password** en condition réelle (le format du lien a été légèrement ajusté)

## 📊 Nouveaux logs disponibles

Consultables dans `/var/www/gmao/logs/gmao.log` :
- `[LOGIN]` succès/échec avec IP source
- `[REHASH]` migration bcrypt
- `[RESET]` demandes et confirmations
- `[MIGRATION]` ajouts de colonnes au démarrage
- `[MAIL]` erreurs d'envoi
- `[NOTIFY]` échecs de notification

## 🛠️ Variables d'environnement disponibles

| Variable | Défaut | Description |
|---|---|---|
| `GMAO_DB` | `./gmao.db` | Chemin vers la base SQLite |
| `GMAO_CORS_ORIGINS` | liste localhost/127.0.0.1 | Origines CORS autorisées (CSV) |
| `GMAO_TOKEN_TTL` | `604800` | Durée de vie token en secondes (7j) |
