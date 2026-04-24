"""
SOCOM GMAO — Backend v3.2
Audit hardening: bcrypt, rate limiting, CORS restreint, logging structuré,
token avec expiration, gestion connexions DB, taille payload limitée.
"""
import hashlib, json, os, sqlite3, smtplib, io, logging, secrets, time, re
from datetime import datetime, date, timedelta
from functools import wraps
from pathlib import Path
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, jsonify, request, send_file, Response, g

# bcrypt en optionnel (fallback SHA-256 pour la migration progressive)
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

# Rate limiting en optionnel (warning si absent)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False

from flask_cors import CORS

BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.environ.get("GMAO_DB", str(BASE_DIR / "gmao.db"))

# ── Logging structuré avec rotation ──
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
logger = logging.getLogger("gmao")
logger.setLevel(logging.INFO)
_h = RotatingFileHandler(str(LOG_DIR / "gmao.log"), maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
_h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_h)
# Aussi en console (stdout gunicorn)
_sh = logging.StreamHandler()
_sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_sh)

app = Flask(__name__)
# Limite de taille de requête : 10 Mo (empêche DoS via payload base64 énorme)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["JSON_SORT_KEYS"] = False

# ── CORS : restreindre aux origines légitimes via env, wildcard en fallback ──
_cors_env = os.environ.get("GMAO_CORS_ORIGINS", "")
if _cors_env.strip():
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    # Fallback: origines locales + wildcard en dev. En prod, DÉFINIR GMAO_CORS_ORIGINS.
    _cors_origins = ["http://localhost", "http://127.0.0.1", "http://localhost:5173",
                     "http://localhost:8000", "http://187.127.68.131"]
    logger.warning("GMAO_CORS_ORIGINS non defini — utilisation de la liste par defaut. "
                   "DEFINIR cette variable en production avec le(s) domaine(s) autorise(s).")
CORS(app, origins=_cors_origins, supports_credentials=False)

# ── Rate limiting (login, reset password) ──
if HAS_LIMITER:
    limiter = Limiter(get_remote_address, app=app,
                      default_limits=[], storage_uri="memory://")
else:
    # Stub qui no-op si la lib n'est pas là
    class _NoopLimiter:
        def limit(self, *a, **k):
            def deco(fn): return fn
            return deco
    limiter = _NoopLimiter()
    logger.warning("flask-limiter non installe — rate limiting desactive. "
                   "Installer avec: pip install flask-limiter")

# ── Token d'auth : durée de vie (secondes), configurable ──
TOKEN_TTL = int(os.environ.get("GMAO_TOKEN_TTL", 60 * 60 * 24 * 7))  # 7 jours par defaut
# Secret serveur utilisé pour signer les tokens (persistant entre redémarrages)
# Stocké dans parametres_app à la première utilisation
_SERVER_SECRET_CACHE = None

# Hook global : gestion d'erreur JSON uniforme + payload trop gros
@app.errorhandler(413)
def _too_large(e):
    return jsonify({"error": "Payload trop volumineux (max 10 Mo)"}), 413

@app.errorhandler(429)
def _too_many(e):
    return jsonify({"error": "Trop de requetes, veuillez reessayer plus tard"}), 429

@app.route("/")
def index():
    f = BASE_DIR / "index.html"
    return send_file(str(f)) if f.exists() else ("index.html introuvable", 404)

@app.route("/mobile")
def mobile():
    f = BASE_DIR / "gmao_mobile.html"
    if not f.exists(): return ("gmao_mobile.html introuvable", 404)
    resp = send_file(str(f))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp

@app.route("/sw.js")
def sw():
    f = BASE_DIR / "sw.js"
    if not f.exists(): return ("", 404)
    return Response(f.read_text(), mimetype="application/javascript",
                    headers={
                        "Service-Worker-Allowed": "/",
                        "Cache-Control": "no-cache, no-store, must-revalidate"
                    })

@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "SOCOM GMAO",
        "short_name": "SOCOM",
        "description": "GMAO Terrain SOCOM",
        "start_url": "/mobile",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#0F1E3D",
        "theme_color": "#0F1E3D",
        "icons": [
            {"src": "/icons/socom-icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/icons/socom-icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": "/icons/socom-icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}
        ]
    })

@app.route("/icons/<path:filename>")
def icons(filename):
    """Sert les icônes PWA depuis le dossier icons/."""
    # Sécurité : empêcher path traversal
    if ".." in filename or filename.startswith("/"):
        return "", 404
    f = BASE_DIR / "icons" / filename
    if not f.exists() or not f.is_file():
        return "", 404
    # Cache long côté navigateur (les icônes ne changent pas)
    resp = send_file(str(f))
    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp

@app.route("/assets/<path:filename>")
def assets(filename):
    """Sert les assets (logos, images) depuis le dossier assets/."""
    if ".." in filename or filename.startswith("/"):
        return "", 404
    f = BASE_DIR / "assets" / filename
    if not f.exists() or not f.is_file():
        return "", 404
    resp = send_file(str(f))
    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp

@app.route("/health")
def health():
    try: get_db().execute("SELECT 1"); return jsonify({"status":"ok","time":now()})
    except Exception as e: return jsonify({"status":"error","error":str(e)}),500

def hp(pw):
    """Hash SHA-256 conservé pour rétro-compatibilité (vérification legacy)."""
    return hashlib.sha256(pw.encode()).hexdigest()

def hash_password(pw):
    """Hash moderne avec bcrypt si dispo, fallback SHA-256 sinon.
    Retourne une chaîne préfixée par 'bcrypt$' ou 'sha256$' pour discriminer."""
    if HAS_BCRYPT:
        salt = bcrypt.gensalt(rounds=12)
        return "bcrypt$" + bcrypt.hashpw(pw.encode(), salt).decode()
    return "sha256$" + hp(pw)

def verify_password(pw, stored):
    """Vérifie un mot de passe contre un hash stocké.
    Supporte 3 formats: bcrypt$..., sha256$..., ou legacy SHA-256 nu (64 hex)."""
    if not stored:
        return False
    if stored.startswith("bcrypt$"):
        if not HAS_BCRYPT:
            return False
        try:
            return bcrypt.checkpw(pw.encode(), stored[7:].encode())
        except Exception:
            return False
    if stored.startswith("sha256$"):
        return stored[7:] == hp(pw)
    # Legacy : hash SHA-256 brut de 64 caractères hex
    if len(stored) == 64 and all(c in "0123456789abcdef" for c in stored.lower()):
        return stored == hp(pw)
    return False

def needs_rehash(stored):
    """True si le hash stocké n'est pas au format bcrypt (et bcrypt dispo)."""
    return HAS_BCRYPT and not stored.startswith("bcrypt$")

def now(): return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
def today(): return date.today().isoformat()
def rows(cur): return [dict(r) for r in cur.fetchall()]
def one(cur): r = cur.fetchone(); return dict(r) if r else None
def to_int(v):
    try: return int(v) if v not in (None,"","null") else None
    except (ValueError, TypeError): return None

# ── Whitelist des colonnes modifiables par table (remplace la confiance aveugle dans les f-string UPDATE) ──
ALLOWED_UPDATE_COLS = {
    "techniciens_astreinte": {"nom","gsm","couleur","actif"},
    "astreinte_specialites": {"nom","description","ordre"},
    "compteur_types":        {"nom","description"},
    "compteurs":             {"type_id","nom","numero","unite","localisation"},
    "graphiques_config":     {"titre","ordre","series","comparaison"},
    "parametres_rapport":    {"parametre","valeur","ordre"},
    "utilisateurs":          {"nom","email","role","actif","password","token_version","matricule","manager_id","techniques","poste_id","superieur_id"},
    "clients":               {"societe","nom","prenom","email","telephone","notes"},
    "projets":               {"numero_projet","nom","client_id","manager_id","description",
                              "date_debut","date_fin","statut","deplacement_km","nb_deplacements"},
    "equipements":           {"designation","type_technique","localisation","marque","modele",
                              "puissance","numero_serie","in_out","date_mise_en_service","statut",
                              "gamme_id","technique_id","notes","planning_id","semaine_planif",
                              "jour_semaine_planif","intervention_samedi","intervention_dimanche"},
    "pieces":                {"type_piece","date_installation","duree_vie_estimee",
                              "date_fin_de_vie","statut","quantite","numero_serie",
                              "reference","commentaire"},
    "equipes":               {"nom","manager_id"},
    "interventions":         {"equipement_id","technicien_id","equipe_id","type","statut",
                              "date_prevue","date_realisation","description","rapport","heure_prevue"},
    "comptes_rendus":        {"date_intervention","observations","actions_realisees",
                              "mesures","recommandations","conclusion"},
    "techniques":            {"nom","description"},
    "gammes":                {"nom","periodicite","temps"},
    "smtp_config":           {"host","port","username","password","sender_email",
                              "sender_name","use_tls","enabled"},
    "plannings":             {"nom","equipe_id","heures_par_jour","heure_debut"},
}

def safe_update(db, table, id_value, fields, id_col="id"):
    """UPDATE sécurisé avec whitelist de colonnes. Retourne le nb de colonnes modifiées."""
    allowed = ALLOWED_UPDATE_COLS.get(table, set())
    sets, params = [], []
    for col, val in fields.items():
        if col in allowed:
            sets.append(f"{col}=?")
            params.append(val)
    if not sets:
        return 0
    params.append(id_value)
    db.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE {id_col}=?", params)
    return len(sets)

def get_db():
    """Récupère/crée la connexion SQLite liée au contexte de requête.
    Fermeture automatique via teardown_appcontext."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db

@app.teardown_appcontext
def _close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        try: db.close()
        except Exception: pass

def _get_server_secret():
    """Secret HMAC serveur (généré au premier démarrage, persisté en BDD)."""
    global _SERVER_SECRET_CACHE
    if _SERVER_SECRET_CACHE:
        return _SERVER_SECRET_CACHE
    db = get_db()
    r = one(db.execute("SELECT valeur FROM parametres_app WHERE cle='server_secret'"))
    if r and r["valeur"]:
        _SERVER_SECRET_CACHE = r["valeur"]
        return _SERVER_SECRET_CACHE
    secret = secrets.token_hex(32)
    db.execute("INSERT OR REPLACE INTO parametres_app (cle,valeur) VALUES ('server_secret',?)", (secret,))
    db.commit()
    _SERVER_SECRET_CACHE = secret
    return secret

def _sign(data):
    """HMAC-SHA256 hex court pour signer un token."""
    import hmac
    return hmac.new(_get_server_secret().encode(), data.encode(), hashlib.sha256).hexdigest()

def make_token(user):
    """Token signé: uid.issued_at.token_version.signature — expirable + révocable."""
    iat = int(time.time())
    tv = user.get("token_version") or 0
    payload = f"{user['id']}.{iat}.{tv}"
    sig = _sign(payload)
    return f"{payload}.{sig}"

def verify_token(token):
    """Retourne l'utilisateur si le token est valide, sinon None."""
    if not token or "." not in token:
        return None
    parts = token.split(".")
    if len(parts) != 4:
        return None
    try:
        uid_s, iat_s, tv_s, sig = parts
        uid = int(uid_s); iat = int(iat_s); tv = int(tv_s)
    except (ValueError, TypeError):
        return None
    # Vérif signature
    payload = f"{uid}.{iat}.{tv}"
    import hmac
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    # Vérif expiration
    if time.time() - iat > TOKEN_TTL:
        return None
    # Vérif utilisateur + token_version (permet révocation par changement de MDP)
    db = get_db()
    u = one(db.execute("SELECT * FROM utilisateurs WHERE id=? AND actif=1", (uid,)))
    if not u:
        return None
    current_tv = u.get("token_version") or 0
    if current_tv != tv:
        return None
    return u

def _authenticate():
    """Lit l'Authorization header, valide token moderne OU legacy.
    Retourne l'utilisateur ou None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    # Format moderne : 4 segments séparés par '.'
    if token.count(".") == 3:
        return verify_token(token)
    # Legacy : ancien format "uid:hash" — accepté pour compat ascendante
    if ":" in token:
        parts = token.split(":")
        if len(parts) == 2:
            uid = to_int(parts[0])
            if uid:
                db = get_db()
                u = one(db.execute("SELECT * FROM utilisateurs WHERE id=? AND actif=1",(uid,)))
                if u and hp(f"{uid}:{u['email']}:{u['password']}") == parts[1]:
                    return u
    return None

def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        u = _authenticate()
        if not u:
            return jsonify({"error":"Non authentifie"}), 401
        request.user = u
        return fn(*a, **k)
    return wrapper

def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            u = _authenticate()
            if not u:
                return jsonify({"error":"Non authentifie"}), 401
            if u["role"] not in roles:
                return jsonify({"error":"Acces refuse"}), 403
            request.user = u
            return fn(*a, **k)
        return wrapper
    return decorator

def criticite(eid,db):
    p=one(db.execute("SELECT COUNT(*) AS n FROM pieces WHERE equipement_id=? AND statut='A_REMPLACER'",(eid,)))
    if p and p["n"]>0: return "CRITIQUE"
    p2=one(db.execute("SELECT COUNT(*) AS n FROM pieces WHERE equipement_id=? AND statut='A_SURVEILLER'",(eid,)))
    if p2 and p2["n"]>0: return "A_SURVEILLER"
    return "OK"

def statut_piece(fdv_):
    if not fdv_: return "OK"
    try:
        d=(datetime.strptime(fdv_,"%Y-%m-%d").date()-date.today()).days
        return "A_REMPLACER" if d<0 else "A_SURVEILLER" if d<=365 else "OK"
    except: return "OK"

def next_numero(db,prefix,table,col):
    r=one(db.execute(f"SELECT MAX(CAST(SUBSTR({col},LENGTH(?)+1) AS INTEGER)) AS m FROM {table} WHERE {col} LIKE ?",(prefix,prefix+"%")))
    return f"{prefix}{((r['m'] or 0)+1):05d}"

def send_mail(to,subj,body,attachments=None):
    try:
        db=get_db(); cfg=one(db.execute("SELECT * FROM smtp_config WHERE id=1"))
        if not cfg or not cfg["enabled"]: return
        msg=MIMEMultipart(); msg["From"]=f"{cfg['sender_name']} <{cfg['sender_email']}>"
        msg["To"]=to; msg["Subject"]=subj; msg.attach(MIMEText(body,"plain","utf-8"))
        if attachments:
            from email.mime.base import MIMEBase; from email import encoders
            for fname,fdata in attachments:
                part=MIMEBase('application','octet-stream'); part.set_payload(fdata)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition',f'attachment; filename="{fname}"')
                msg.attach(part)
        with smtplib.SMTP(cfg["host"],cfg["port"],timeout=10) as s:
            if cfg["use_tls"]: s.starttls()
            if cfg["username"]: s.login(cfg["username"],cfg["password"])
            s.sendmail(cfg["sender_email"],to,msg.as_string())
        try:
            db.execute("INSERT INTO mail_log (destinataire,sujet,statut) VALUES (?,?,?)",(to,subj,"ENVOYE"))
            db.commit()
        except Exception as e_log:
            logger.warning(f"mail_log insert failed: {e_log}")
    except Exception as e:
        logger.error(f"[MAIL] echec envoi vers {to}: {e}")
        try:
            db2=get_db()
            db2.execute("INSERT INTO mail_log (destinataire,sujet,statut,erreur) VALUES (?,?,?,?)",(to,subj,"ERREUR",str(e)))
            db2.commit()
        except Exception as e_log:
            logger.warning(f"mail_log error insert failed: {e_log}")

def log_action(user, action, entity_type="", entity_id=None, entity_label="", details=""):
    """Enregistre une action utilisateur dans la table logs pour audit.
    
    Args:
        user: dict utilisateur (request.user) ou None pour actions anonymes
        action: code action (LOGIN, CREATE, UPDATE, DELETE, etc.)
        entity_type: type d'entité concernée (intervention, utilisateur, projet, etc.)
        entity_id: id de l'entité
        entity_label: libellé lisible de l'entité (ex: nom, numéro)
        details: texte libre ou JSON pour info complémentaire
    """
    try:
        db = get_db()
        uid = (user or {}).get("id")
        unom = (user or {}).get("nom", "") or ""
        db.execute(
            "INSERT INTO logs (user_id, user_nom, action, entity_type, entity_id, entity_label, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uid, unom, action, entity_type or "", entity_id, entity_label or "", details or "")
        )
        db.commit()
    except Exception as e:
        logger.warning(f"[log_action] échec: {e}")

def notify(iid,action):
    try:
        db=get_db()
        r=one(db.execute("""SELECT i.numero,i.type,i.statut,e.designation,p.nom AS projet,
               u.email AS mgr_email,u.nom AS mgr_nom,i.date_realisation
               FROM interventions i JOIN equipements e ON i.equipement_id=e.id
               JOIN projets p ON e.projet_id=p.id
               LEFT JOIN utilisateurs u ON p.manager_id=u.id WHERE i.id=?""",(iid,)))
        if not r or not r["mgr_email"]: return
        attachments=[]
        if r["statut"]=="TERMINEE":
            try:
                from rapport_pdf import generate_rapport
                # Récupère intervention complète (description, localisation, technique)
                iv_full = one(db.execute("""SELECT i.*, e.localisation, e.marque, e.modele, e.technique_id
                    FROM interventions i JOIN equipements e ON e.id=i.equipement_id WHERE i.id=?""", (iid,)))
                iv_full = iv_full or {}
                crs=rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
                for cr in crs:
                    cr["intervenants"]=rows(db.execute("""
                        SELECT ci.*,COALESCE(u2.nom,ci.nom,'') AS nom
                        FROM cr_intervenants ci LEFT JOIN utilisateurs u2 ON ci.utilisateur_id=u2.id
                        WHERE ci.cr_id=? ORDER BY ci.id""",(cr["id"],)))
                # Construction de la liste structurée des CRs
                comptes_rendus_pdf=[]
                for cr in crs:
                    ivs=[]
                    for iv in cr.get("intervenants",[]):
                        nom2=iv.get("nom","") or ""
                        if not nom2 and iv.get("utilisateur_id"):
                            u2=one(db.execute("SELECT nom FROM utilisateurs WHERE id=?",(iv["utilisateur_id"],)))
                            if u2: nom2=u2["nom"]
                        ivs.append({
                            "nom": nom2 or "—",
                            "date": iv.get("date","") or cr.get("date_intervention",""),
                            "heure_debut": iv.get("heure_debut",""),
                            "heure_fin": iv.get("heure_fin",""),
                            "total_heures": iv.get("total_heures",0)
                        })
                    comptes_rendus_pdf.append({
                        "date": cr.get("date_intervention","") or "—",
                        "numero": cr.get("numero","") or "",
                        "observations": cr.get("observations","") or "",
                        "intervenants": ivs
                    })
                # Technicien principal (fallback)
                tech_nom_r=one(db.execute("SELECT nom FROM utilisateurs WHERE id=?",(r.get("technicien_id","0"),)))
                tech_nom=tech_nom_r["nom"] if tech_nom_r else "—"
                # Liste des intervenants uniques
                noms_set=set(); noms_list=[]
                for cr in comptes_rendus_pdf:
                    for iv in cr.get("intervenants",[]):
                        n=iv.get("nom","")
                        if n and n!="—" and n not in noms_set:
                            noms_set.add(n); noms_list.append(n)
                if not noms_list: noms_list=[tech_nom]
                # Date
                date_iv = (comptes_rendus_pdf[0]["date"] if comptes_rendus_pdf else (r.get("date_realisation") or today()))
                date_iv = (date_iv or "").split("\n")[0][:10]
                # Équipement enrichi
                marque_modele = f"{iv_full.get('marque','')} {iv_full.get('modele','')}".strip() or "—"
                # Technique nom
                technique_nom = "—"
                if iv_full.get("technique_id"):
                    tr_row = one(db.execute("SELECT nom FROM techniques WHERE id=?", (iv_full["technique_id"],)))
                    if tr_row: technique_nom = tr_row["nom"]
                pdf_bytes = generate_rapport({
                    "type_label": r["type"],
                    "numero_iv": r["numero"],
                    "date": date_iv,
                    "client": r["projet"],
                    "numero_projet": r.get("numero_projet","") or "—",
                    "projet_nom": "",
                    "equipement": r["designation"],
                    "marque_modele": marque_modele,
                    "localisation": iv_full.get("localisation","") or "—",
                    "technique": technique_nom,
                    "intervenants": ", ".join(noms_list),
                    "description": iv_full.get("description","") or "",
                    "comptes_rendus": comptes_rendus_pdf,
                })
                attachments.append((f"Rapport_{r['numero']}.pdf",pdf_bytes))
            except Exception as pe: logger.warning(f"[PDF] generation rapport echouee: {pe}")
        send_mail(r["mgr_email"],f"[GMAO] {action} - {r['numero']}",
            f"Bonjour {r['mgr_nom']},\n\n{action}\n\nRef: {r['numero']}\nType: {r['type']}\nStatut: {r['statut']}\nEquipement: {r['designation']}\nProjet: {r['projet']}\n\nCordialement,\nSOCOM GMAO",
            attachments=attachments or None)
    except Exception as e: logger.error(f"[NOTIFY] echec iid={iid}: {e}")

def init_db():
    db=get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'technicien'
            CHECK(role IN ('admin','manager','technicien','acl')),
        actif INTEGER DEFAULT 1, matricule TEXT DEFAULT '',
        manager_id INTEGER REFERENCES utilisateurs(id) ON DELETE SET NULL,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT, societe TEXT NOT NULL,
        nom TEXT DEFAULT '', prenom TEXT DEFAULT '', email TEXT DEFAULT '',
        telephone TEXT DEFAULT '', notes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS projets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, numero_projet TEXT DEFAULT '',
        nom TEXT NOT NULL, client_id INTEGER REFERENCES clients(id),
        manager_id INTEGER REFERENCES utilisateurs(id),
        description TEXT DEFAULT '', date_debut TEXT, date_fin TEXT,
        statut TEXT DEFAULT 'EN_COURS', created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS equipements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        projet_id INTEGER NOT NULL REFERENCES projets(id),
        designation TEXT NOT NULL, type_technique TEXT NOT NULL,
        localisation TEXT DEFAULT '', marque TEXT DEFAULT '', modele TEXT DEFAULT '',
        puissance TEXT DEFAULT '', numero_serie TEXT DEFAULT '', in_out TEXT DEFAULT '',
        date_mise_en_service TEXT, statut TEXT NOT NULL DEFAULT 'EN_SERVICE',
        gamme_id INTEGER, technique_id INTEGER,
        notes TEXT, created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS equipement_gammes (
        equipement_id INTEGER NOT NULL, gamme_id INTEGER NOT NULL,
        PRIMARY KEY (equipement_id, gamme_id)
    );
    CREATE TABLE IF NOT EXISTS techniques (
        id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '', created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS gammes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT NOT NULL,
        periodicite TEXT NOT NULL, temps TEXT DEFAULT '00h00', created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS gamme_operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gamme_id INTEGER NOT NULL REFERENCES gammes(id) ON DELETE CASCADE,
        ordre INTEGER DEFAULT 0, description TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pieces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        equipement_id INTEGER NOT NULL REFERENCES equipements(id),
        type_piece TEXT NOT NULL, date_installation TEXT,
        duree_vie_estimee INTEGER, date_fin_de_vie TEXT,
        statut TEXT NOT NULL DEFAULT 'OK' CHECK(statut IN ('OK','A_SURVEILLER','A_REMPLACER')),
        quantite INTEGER DEFAULT 1, numero_serie TEXT DEFAULT '',
        reference TEXT DEFAULT '', commentaire TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS equipes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT NOT NULL,
        manager_id INTEGER REFERENCES utilisateurs(id),
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS equipe_membres (
        equipe_id INTEGER NOT NULL REFERENCES equipes(id),
        technicien_id INTEGER NOT NULL REFERENCES utilisateurs(id),
        PRIMARY KEY (equipe_id, technicien_id)
    );
    CREATE TABLE IF NOT EXISTS interventions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, numero TEXT UNIQUE,
        equipement_id INTEGER NOT NULL REFERENCES equipements(id),
        technicien_id INTEGER REFERENCES utilisateurs(id),
        equipe_id INTEGER REFERENCES equipes(id),
        type TEXT NOT NULL DEFAULT 'MAINTENANCE' CHECK(type IN ('MAINTENANCE','DEPANNAGE')),
        statut TEXT NOT NULL DEFAULT 'PLANIFIEE'
            CHECK(statut IN ('A_PLANIFIER','PLANIFIEE','EN_COURS','TERMINEE','ANNULEE')),
        date_prevue TEXT, date_realisation TEXT,
        description TEXT DEFAULT '', rapport TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS comptes_rendus (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        intervention_id INTEGER NOT NULL REFERENCES interventions(id),
        date_intervention TEXT, observations TEXT DEFAULT '',
        actions_realisees TEXT DEFAULT '', mesures TEXT DEFAULT '',
        recommandations TEXT DEFAULT '', conclusion TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS cr_intervenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cr_id INTEGER NOT NULL REFERENCES comptes_rendus(id) ON DELETE CASCADE,
        utilisateur_id INTEGER REFERENCES utilisateurs(id),
        nom TEXT DEFAULT '', date TEXT DEFAULT '',
        heure_debut TEXT DEFAULT '', heure_fin TEXT DEFAULT '',
        total_heures REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS cr_materiels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cr_id INTEGER NOT NULL REFERENCES comptes_rendus(id) ON DELETE CASCADE,
        designation TEXT NOT NULL,
        quantite REAL DEFAULT 1,
        ordre INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_cr_materiels_cr ON cr_materiels(cr_id);
    CREATE TABLE IF NOT EXISTS intervention_creneaux (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        intervention_id INTEGER NOT NULL REFERENCES interventions(id) ON DELETE CASCADE,
        date TEXT NOT NULL,
        heure_debut TEXT DEFAULT '',
        heure_fin TEXT DEFAULT '',
        technicien_id INTEGER REFERENCES utilisateurs(id),
        notes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_creneaux_intervention ON intervention_creneaux(intervention_id);
    CREATE INDEX IF NOT EXISTS idx_creneaux_date ON intervention_creneaux(date);
    CREATE INDEX IF NOT EXISTS idx_creneaux_tech ON intervention_creneaux(technicien_id);
    CREATE TABLE IF NOT EXISTS intervention_techniciens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        intervention_id INTEGER NOT NULL REFERENCES interventions(id) ON DELETE CASCADE,
        utilisateur_id INTEGER NOT NULL REFERENCES utilisateurs(id),
        UNIQUE(intervention_id, utilisateur_id)
    );
    CREATE INDEX IF NOT EXISTS idx_ivtech_intervention ON intervention_techniciens(intervention_id);
    CREATE INDEX IF NOT EXISTS idx_ivtech_user ON intervention_techniciens(utilisateur_id);
    CREATE TABLE IF NOT EXISTS occupation_types (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        couleur TEXT DEFAULT '#64748b',
        actif INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS occupations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        technicien_id INTEGER NOT NULL REFERENCES utilisateurs(id) ON DELETE CASCADE,
        type_id INTEGER REFERENCES occupation_types(id),
        date TEXT NOT NULL,
        heure_debut TEXT DEFAULT '',
        heure_fin TEXT DEFAULT '',
        total_heures REAL DEFAULT 0,
        notes TEXT DEFAULT '',
        numero_projet TEXT DEFAULT '',
        nom_chantier TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_occ_tech ON occupations(technicien_id);
    CREATE INDEX IF NOT EXISTS idx_occ_date ON occupations(date);
    CREATE INDEX IF NOT EXISTS idx_occ_type ON occupations(type_id);
    CREATE TABLE IF NOT EXISTS smtp_config (
        id INTEGER PRIMARY KEY DEFAULT 1, host TEXT DEFAULT '',
        port INTEGER DEFAULT 587, username TEXT DEFAULT '', password TEXT DEFAULT '',
        sender_email TEXT DEFAULT '', sender_name TEXT DEFAULT 'SOCOM GMAO',
        use_tls INTEGER DEFAULT 1, enabled INTEGER DEFAULT 0
    );
    INSERT OR IGNORE INTO smtp_config (id) VALUES (1);
    CREATE TABLE IF NOT EXISTS plannings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        equipe_id INTEGER REFERENCES equipes(id),
        heures_par_jour REAL DEFAULT 8.0,
        heure_debut TEXT DEFAULT '08:00',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS parametres_rapport (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        projet_id INTEGER NOT NULL REFERENCES projets(id) ON DELETE CASCADE,
        annee INTEGER NOT NULL,
        chapitre TEXT NOT NULL,
        parametre TEXT DEFAULT '',
        valeur TEXT DEFAULT '',
        ordre INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS analyses_rapport (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        projet_id INTEGER NOT NULL REFERENCES projets(id) ON DELETE CASCADE,
        annee INTEGER NOT NULL,
        type_analyse TEXT NOT NULL,
        texte TEXT DEFAULT '',
        updated_at TEXT,
        UNIQUE(projet_id, annee, type_analyse)
    );
    CREATE TABLE IF NOT EXISTS graphiques_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        projet_id INTEGER NOT NULL REFERENCES projets(id) ON DELETE CASCADE,
        titre TEXT NOT NULL DEFAULT 'Graphique',
        ordre INTEGER DEFAULT 0,
        series TEXT DEFAULT '[]',
        comparaison INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS parametres_app (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cle TEXT NOT NULL UNIQUE,
        valeur TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS releves_compteurs (id INTEGER PRIMARY KEY AUTOINCREMENT, cr_id INTEGER NOT NULL REFERENCES comptes_rendus(id) ON DELETE CASCADE, compteur_id INTEGER NOT NULL REFERENCES compteurs(id), valeur REAL, date_releve TEXT, notes TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS compteur_types (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS compteurs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        equipement_id INTEGER NOT NULL REFERENCES equipements(id) ON DELETE CASCADE,
        type_id INTEGER REFERENCES compteur_types(id),
        nom TEXT NOT NULL,
        numero TEXT DEFAULT '',
        unite TEXT DEFAULT '',
        localisation TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS techniciens_astreinte (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        gsm TEXT DEFAULT '',
        couleur TEXT DEFAULT '#3b82f6',
        actif INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS astreinte_specialites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '',
        ordre INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS astreinte_planning (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        specialite_id INTEGER NOT NULL REFERENCES astreinte_specialites(id),
        technicien TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(date, specialite_id)
    );
    CREATE TABLE IF NOT EXISTS mail_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        destinataire TEXT NOT NULL,
        sujet TEXT NOT NULL,
        statut TEXT DEFAULT 'ENVOYE',
        erreur TEXT DEFAULT '',
        intervention_id INTEGER,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS postes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        ordre INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT DEFAULT (datetime('now')),
        user_id INTEGER,
        user_nom TEXT DEFAULT '',
        action TEXT NOT NULL,
        entity_type TEXT DEFAULT '',
        entity_id INTEGER,
        entity_label TEXT DEFAULT '',
        details TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at);
    CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_logs_entity ON logs(entity_type, entity_id);
    """)
    db.commit()

    # ── Migrations idempotentes (remplace les ALTER TABLE éparpillés) ──
    def _add_col(table, col, ddl):
        cols = {r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()}
        if col not in cols:
            try:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
                logger.info(f"[MIGRATION] ajout {table}.{col}")
            except Exception as e:
                logger.error(f"[MIGRATION] echec {table}.{col}: {e}")

    # utilisateurs : token_version (revocation) + reset password
    _add_col("utilisateurs", "token_version",  "INTEGER DEFAULT 0")
    _add_col("utilisateurs", "reset_token",    "TEXT")
    _add_col("utilisateurs", "reset_expires",  "TEXT")

    # plannings (session 7-8)
    for col, ddl in [("equipe_id","INTEGER"), ("heures_par_jour","REAL DEFAULT 8.0"),
                     ("heure_debut","TEXT DEFAULT '08:00'")]:
        _add_col("plannings", col, ddl)

    # equipements (session 7-8)
    for col, ddl in [("planning_id","INTEGER"),("semaine_planif","INTEGER"),
                     ("jour_semaine_planif","INTEGER"),("intervention_samedi","INTEGER DEFAULT 0"),
                     ("intervention_dimanche","INTEGER DEFAULT 0")]:
        _add_col("equipements", col, ddl)

    # equipement_gammes : planif par gamme (session 19+)
    # Chaque gamme associée à un équipement peut avoir sa propre planif.
    # Les colonnes globales sur equipements restent pour compatibilité (ancienne planif).
    for col, ddl in [("planning_id","INTEGER"),("semaine_planif","INTEGER"),
                     ("jour_semaine_planif","INTEGER"),("intervention_samedi","INTEGER DEFAULT 0"),
                     ("intervention_dimanche","INTEGER DEFAULT 0")]:
        _add_col("equipement_gammes", col, ddl)
    # Mode de planification : SEMAINE (semaine ISO fixe, défaut) ou NTH_JOUR_MOIS (ex: 2ème jeudi du mois)
    # nth_semaine_mois : 1..5 (ou -1 pour "dernier") = rang dans le mois
    _add_col("equipement_gammes", "planif_mode", "TEXT DEFAULT 'SEMAINE'")
    _add_col("equipement_gammes", "nth_semaine_mois", "INTEGER")

    # interventions.heure_prevue
    _add_col("interventions", "heure_prevue", "TEXT DEFAULT '08:00'")
    # occupations.numero_projet (pour les occupations de type Offre, format P00000)
    _add_col("occupations", "numero_projet", "TEXT DEFAULT ''")
    # occupations.nom_chantier (obligatoire si type=Offre, accompagne numero_projet)
    _add_col("occupations", "nom_chantier", "TEXT DEFAULT ''")
    # occupations.accompagnants_ids (JSON array des ids de techniciens accompagnants, informatif)
    _add_col("occupations", "accompagnants_ids", "TEXT DEFAULT ''")
    # occupation_types.autorise_accompagnants : 0/1 pour afficher le champ accompagnants
    _add_col("occupation_types", "autorise_accompagnants", "INTEGER DEFAULT 0")
    # utilisateurs.matricule (pour la fiche de pointage SOCOM)
    _add_col("utilisateurs", "matricule", "TEXT DEFAULT ''")
    # utilisateurs.manager_id (le manager d'un technicien pour la fiche de pointage)
    _add_col("utilisateurs", "manager_id", "INTEGER")
    # utilisateurs.techniques : CSV des techniques gérées par un manager technique (ex: "CVC,Electricite")
    _add_col("utilisateurs", "techniques", "TEXT DEFAULT ''")
    # utilisateurs.poste_id : référence à la table postes (organigramme)
    _add_col("utilisateurs", "poste_id", "INTEGER")
    # utilisateurs.superieur_id : supérieur hiérarchique dans l'organigramme visuel
    # (distinct de manager_id qui sert à l'attribution GMAO / fiche de pointage)
    _add_col("utilisateurs", "superieur_id", "INTEGER")
    # projets.deplacement_km : distance A/R pour les dépannages
    # (le nombre de déplacements est saisi au niveau du CR pour les dépannages)
    _add_col("projets", "deplacement_km", "REAL DEFAULT 0")
    _add_col("projets", "nb_deplacements", "INTEGER DEFAULT 0")
    # comptes_rendus.nb_deplacements : nombre de déplacements effectués sur ce CR
    # (repris × km du projet pour la facturation - dépannage uniquement)
    _add_col("comptes_rendus", "nb_deplacements", "INTEGER DEFAULT 0")
    # Garantir la colonne 'numero' sur comptes_rendus (utilisée pour affichage planning CR000032)
    _add_col("comptes_rendus", "numero", "TEXT")
    # Migration one-shot : attribuer un numéro aux CRs qui n'en ont pas
    try:
        missing = rows(db.execute("SELECT id FROM comptes_rendus WHERE numero IS NULL OR numero='' ORDER BY id"))
        for cr_row in missing:
            try:
                new_num = next_numero(db, "CR", "comptes_rendus", "numero")
                db.execute("UPDATE comptes_rendus SET numero=? WHERE id=?", (new_num, cr_row["id"]))
            except Exception as ex:
                logger.warning(f"[migration CR numero] skip id={cr_row['id']} : {ex}")
        if missing:
            db.commit()
            logger.info(f"[migration CR numero] {len(missing)} CR(s) numérotés")
    except Exception as ex:
        logger.warning(f"[migration CR numero] erreur globale : {ex}")

    # Migration : retirer le type OFFRE si présent dans la CHECK constraint.
    # Supprime d'abord tous les bons de type OFFRE (et leurs dépendances en cascade).
    try:
        schema_row = one(db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='interventions'"))
        if schema_row and "'OFFRE'" in (schema_row.get("sql") or ""):
            logger.info("[MIGRATION] retrait du type OFFRE")
            # 1. Compter puis supprimer les bons OFFRE existants
            nb_offre = one(db.execute("SELECT COUNT(*) AS n FROM interventions WHERE type='OFFRE'"))
            nb = (nb_offre and nb_offre.get("n")) or 0
            if nb:
                logger.info(f"[MIGRATION] suppression de {nb} bon(s) de type OFFRE")
                # Supprimer les CR liés + intervenants
                db.execute("""DELETE FROM cr_intervenants WHERE cr_id IN
                              (SELECT cr.id FROM comptes_rendus cr
                               JOIN interventions i ON cr.intervention_id=i.id
                               WHERE i.type='OFFRE')""")
                db.execute("""DELETE FROM comptes_rendus WHERE intervention_id IN
                              (SELECT id FROM interventions WHERE type='OFFRE')""")
                db.execute("DELETE FROM intervention_creneaux WHERE intervention_id IN (SELECT id FROM interventions WHERE type='OFFRE')")
                # Table intervention_techniciens si elle existe
                try:
                    db.execute("DELETE FROM intervention_techniciens WHERE intervention_id IN (SELECT id FROM interventions WHERE type='OFFRE')")
                except Exception:
                    pass
                db.execute("DELETE FROM interventions WHERE type='OFFRE'")
                db.commit()
            # 2. Recréer la table avec CHECK resserré
            db.execute("PRAGMA foreign_keys=OFF")
            db.executescript("""
                CREATE TABLE interventions_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, numero TEXT UNIQUE,
                    equipement_id INTEGER NOT NULL REFERENCES equipements(id),
                    technicien_id INTEGER REFERENCES utilisateurs(id),
                    equipe_id INTEGER REFERENCES equipes(id),
                    type TEXT NOT NULL DEFAULT 'MAINTENANCE'
                        CHECK(type IN ('MAINTENANCE','DEPANNAGE')),
                    statut TEXT NOT NULL DEFAULT 'PLANIFIEE'
                        CHECK(statut IN ('A_PLANIFIER','PLANIFIEE','EN_COURS','TERMINEE','ANNULEE')),
                    date_prevue TEXT, date_realisation TEXT,
                    description TEXT DEFAULT '', rapport TEXT DEFAULT '',
                    created_at TEXT DEFAULT (datetime('now')),
                    heure_prevue TEXT DEFAULT '08:00'
                );
                INSERT INTO interventions_new
                    (id, numero, equipement_id, technicien_id, equipe_id, type, statut,
                     date_prevue, date_realisation, description, rapport, created_at, heure_prevue)
                SELECT id, numero, equipement_id, technicien_id, equipe_id, type, statut,
                       date_prevue, date_realisation, description, rapport, created_at,
                       COALESCE(heure_prevue, '08:00')
                FROM interventions;
                DROP TABLE interventions;
                ALTER TABLE interventions_new RENAME TO interventions;
            """)
            db.execute("PRAGMA foreign_keys=ON")
            db.commit()
            logger.info("[MIGRATION] table interventions recreee sans OFFRE")
    except Exception as e:
        logger.error(f"[MIGRATION] echec retrait OFFRE: {e}")

    # Migration : élargir CHECK statut pour inclure A_PLANIFIER
    # (utilisé quand un bon est créé sans date/tech, à planifier ultérieurement)
    try:
        r = one(db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='interventions'"))
        if r and r.get("sql") and "A_PLANIFIER" not in r["sql"]:
            logger.info("[MIGRATION] ajout A_PLANIFIER au CHECK statut interventions")
            db.execute("PRAGMA foreign_keys=OFF")
            db.executescript("""
                CREATE TABLE interventions_new2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, numero TEXT UNIQUE,
                    equipement_id INTEGER NOT NULL REFERENCES equipements(id),
                    technicien_id INTEGER REFERENCES utilisateurs(id),
                    equipe_id INTEGER REFERENCES equipes(id),
                    type TEXT NOT NULL DEFAULT 'MAINTENANCE'
                        CHECK(type IN ('MAINTENANCE','DEPANNAGE')),
                    statut TEXT NOT NULL DEFAULT 'PLANIFIEE'
                        CHECK(statut IN ('A_PLANIFIER','PLANIFIEE','EN_COURS','TERMINEE','ANNULEE')),
                    date_prevue TEXT, date_realisation TEXT,
                    description TEXT DEFAULT '', rapport TEXT DEFAULT '',
                    created_at TEXT DEFAULT (datetime('now')),
                    heure_prevue TEXT DEFAULT '08:00'
                );
                INSERT INTO interventions_new2
                    (id, numero, equipement_id, technicien_id, equipe_id, type, statut,
                     date_prevue, date_realisation, description, rapport, created_at, heure_prevue)
                SELECT id, numero, equipement_id, technicien_id, equipe_id, type, statut,
                       date_prevue, date_realisation, description, rapport, created_at,
                       COALESCE(heure_prevue, '08:00')
                FROM interventions;
                DROP TABLE interventions;
                ALTER TABLE interventions_new2 RENAME TO interventions;
            """)
            db.execute("PRAGMA foreign_keys=ON")
            db.commit()
            logger.info("[MIGRATION] table interventions recreee avec A_PLANIFIER")
    except Exception as e:
        logger.error(f"[MIGRATION] echec ajout A_PLANIFIER: {e}")

    # Nettoyage table orpheline utilisateurs_new (si présente)
    try:
        r = one(db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='utilisateurs_new'"))
        if r:
            db.execute("DROP TABLE utilisateurs_new")
            logger.info("[MIGRATION] table orpheline 'utilisateurs_new' supprimee")
    except Exception as e:
        logger.warning(f"[MIGRATION] drop utilisateurs_new: {e}")

    db.commit()

    # Seed types d'occupation par défaut (première installation uniquement)
    try:
        r = one(db.execute("SELECT COUNT(*) AS n FROM occupation_types"))
        if r and r["n"] == 0:
            defaults = [
                ("Congés",    "#10B981"),  # vert
                ("Formation", "#6366F1"),  # violet
                ("Maladie",   "#EF4444"),  # rouge
                ("RTT",       "#F59E0B"),  # orange
                ("Réunion",   "#3B82F6"),  # bleu
                ("Offre",     "#A855F7"),  # pourpre - chiffrage / préparation commerciale
                ("Autre",     "#64748B"),  # gris
            ]
            for nom, couleur in defaults:
                db.execute("INSERT OR IGNORE INTO occupation_types (nom, couleur) VALUES (?,?)", (nom, couleur))
            db.commit()
            logger.info("[SEED] types d'occupation par défaut crées")
        # S'assurer que "Offre" existe (installations antérieures)
        has_offre = one(db.execute("SELECT id FROM occupation_types WHERE nom='Offre'"))
        if not has_offre:
            db.execute("INSERT INTO occupation_types (nom, couleur) VALUES (?,?)", ("Offre","#A855F7"))
            db.commit()
            logger.info("[SEED] type 'Offre' ajoute (installation existante)")
    except Exception as e:
        logger.error(f"[SEED occupations] echec: {e}")

    # Seed admin par défaut (première installation uniquement)
    try:
        r = one(db.execute("SELECT COUNT(*) AS n FROM utilisateurs"))
        if r and r["n"] == 0:
            db.execute("INSERT INTO utilisateurs (nom,email,password,role) VALUES (?,?,?,?)",
                       ("Administrateur","admin@gmao.fr",hash_password("admin"),"admin"))
            db.commit()
            logger.warning("[SEED] compte admin par defaut cree (admin@gmao.fr / admin) — A CHANGER !")
    except Exception as e:
        logger.error(f"[SEED] echec: {e}")

with app.app_context(): init_db()


# ══ DASHBOARD ══
@app.route("/api/dashboard")
@require_auth
def get_dashboard():
    db = get_db()
    u  = request.user
    td = today()
    # Filtre selon rôle
    role_filter = ""
    role_params = []
    if u["role"] == "technicien":
        # Technicien : uniquement ses bons (colonne legacy, équipe, ou liaison multi-tech)
        role_filter = (" AND (i.technicien_id=? "
                       "OR i.equipe_id IN (SELECT equipe_id FROM equipe_membres WHERE technicien_id=?) "
                       "OR EXISTS (SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND it.utilisateur_id=?))")
        role_params = [u["id"], u["id"], u["id"]]
    elif u["role"] == "manager":
        # Manager : bons dont il gère le projet, OU équipe (techs dont manager_id=lui), OU techniques gérées
        # Récupérer ses techniques
        udb = one(db.execute("SELECT techniques FROM utilisateurs WHERE id=?", (u["id"],)))
        tech_csv = (udb and udb.get("techniques")) or ""
        tech_list = [t.strip() for t in tech_csv.split(",") if t.strip()]
        conditions = [
            "i.equipement_id IN (SELECT e.id FROM equipements e JOIN projets p ON e.projet_id=p.id WHERE p.manager_id=?)",
            "i.technicien_id=?",
            "i.technicien_id IN (SELECT id FROM utilisateurs WHERE manager_id=?)",
            "EXISTS (SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND "
            "  (it.utilisateur_id=? OR it.utilisateur_id IN (SELECT id FROM utilisateurs WHERE manager_id=?)))"
        ]
        role_params = [u["id"], u["id"], u["id"], u["id"], u["id"]]
        if tech_list:
            placeholders = ",".join(["?"] * len(tech_list))
            conditions.append(f"i.equipement_id IN (SELECT e.id FROM equipements e WHERE e.type_technique IN ({placeholders}))")
            role_params += tech_list
        role_filter = " AND (" + " OR ".join(conditions) + ")"
    # Filtre manager optionnel pour admin (liste déroulante dashboard)
    manager_id = to_int(request.args.get("manager_id")) if u["role"] == "admin" else None

    # KPI compteurs
    kpi = {
        "a_planifier": one(db.execute(f"SELECT COUNT(*) AS n FROM interventions i WHERE i.statut='PLANIFIEE'{role_filter}", role_params))["n"],
        "en_cours":    one(db.execute(f"SELECT COUNT(*) AS n FROM interventions i WHERE i.statut='EN_COURS'{role_filter}", role_params))["n"],
        "terminees":   one(db.execute(f"SELECT COUNT(*) AS n FROM interventions i WHERE i.statut='TERMINEE' AND strftime('%Y-%m',i.date_realisation)=strftime('%Y-%m','now'){role_filter}", role_params))["n"],
    }

    # Interventions du jour
    manager_filter = ""
    manager_params = []
    if manager_id:
        manager_filter = " AND p.manager_id=?"
        manager_params = [manager_id]
    sql_today = f"""SELECT i.*,e.designation AS equip_nom,e.type_technique,
                    p.nom AS projet_nom,u2.nom AS technicien_nom
                    FROM interventions i JOIN equipements e ON i.equipement_id=e.id
                    JOIN projets p ON e.projet_id=p.id
                    LEFT JOIN utilisateurs u2 ON i.technicien_id=u2.id
                    WHERE i.statut NOT IN ('TERMINEE','ANNULEE')
                    AND date(i.date_prevue)=?{role_filter}{manager_filter}
                    ORDER BY i.date_prevue"""
    today_ivs = rows(db.execute(sql_today, [td] + role_params + manager_params))

    # Retards
    sql_retards = f"""SELECT i.*,e.designation AS equip_nom,e.type_technique,
                    p.nom AS projet_nom,u2.nom AS technicien_nom
                    FROM interventions i JOIN equipements e ON i.equipement_id=e.id
                    JOIN projets p ON e.projet_id=p.id
                    LEFT JOIN utilisateurs u2 ON i.technicien_id=u2.id
                    WHERE i.statut NOT IN ('TERMINEE','ANNULEE')
                    AND i.date_prevue IS NOT NULL AND date(i.date_prevue) < ?{role_filter}{manager_filter}
                    ORDER BY i.date_prevue"""
    retards = rows(db.execute(sql_retards, [td] + role_params + manager_params))

    # Alertes pièces
    alertes = rows(db.execute("""SELECT p.*,e.designation AS equip_nom,pr.nom AS projet_nom
        FROM pieces p JOIN equipements e ON p.equipement_id=e.id
        JOIN projets pr ON e.projet_id=pr.id
        WHERE p.statut IN ('A_SURVEILLER','A_REMPLACER') ORDER BY p.statut DESC LIMIT 10"""))

    # Équipements critiques
    critiques = rows(db.execute("""SELECT e.*,p.nom AS projet_nom FROM equipements e
        JOIN projets p ON e.projet_id=p.id
        WHERE e.id IN (SELECT DISTINCT equipement_id FROM pieces WHERE statut='A_REMPLACER') LIMIT 10"""))

    # Stats délais
    r_dep = one(db.execute("""SELECT COUNT(*) AS nb,
        AVG(CAST((JULIANDAY(date_realisation)-JULIANDAY(created_at)) AS REAL)) AS moy
        FROM interventions WHERE type='DEPANNAGE' AND statut='TERMINEE' AND date_realisation IS NOT NULL"""))
    r_mai = one(db.execute("""SELECT COUNT(*) AS nb,
        AVG(CAST((JULIANDAY(date_realisation)-JULIANDAY(created_at)) AS REAL)) AS moy
        FROM interventions WHERE type='MAINTENANCE' AND statut='TERMINEE' AND date_realisation IS NOT NULL"""))

    stats = {
        "moy_jours_depannage":  round(r_dep["moy"] or 0, 1) if r_dep else 0,
        "nb_depannages":        r_dep["nb"] if r_dep else 0,
        "moy_jours_maintenance": round(r_mai["moy"] or 0, 1) if r_mai else 0,
        "nb_maintenances":      r_mai["nb"] if r_mai else 0,
    }

    return jsonify({
        "kpi": kpi,
        "today": today_ivs,
        "retards": retards,
        "alertes": alertes,
        "critiques": critiques,
        "stats": stats
    })


# ══ MOT DE PASSE OUBLIÉ ══
@app.route("/api/reset-password", methods=["POST"])
@limiter.limit("5 per hour")
def request_reset():
    d  = request.json or {}
    email = (d.get("email","") or "").strip().lower()
    if not email: return jsonify({"error":"Email requis"}),400
    db = get_db()
    u = one(db.execute("SELECT * FROM utilisateurs WHERE lower(email)=? AND actif=1",(email,)))
    if not u:
        # Ne pas révéler si l'email existe ou non
        return jsonify({"ok":True})
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    # Les colonnes reset_token et reset_expires sont créées dans init_db (migrations)
    db.execute("UPDATE utilisateurs SET reset_token=?,reset_expires=? WHERE id=?",(token,expires,u["id"]))
    db.commit()
    base_url = request.headers.get("Origin","http://"+request.host)
    # Construire le lien : si la demande vient de /mobile, renvoyer vers /mobile
    referer = request.headers.get("Referer","") or ""
    path_suffix = "/mobile" if "/mobile" in referer else ""
    reset_link = f"{base_url}{path_suffix}?reset_token={token}"
    body = f"""Bonjour {u['nom']},

Vous avez demandé la réinitialisation de votre mot de passe SOCOM GMAO.

Cliquez sur ce lien pour définir un nouveau mot de passe (valable 1 heure) :
{reset_link}

Si vous n'avez pas fait cette demande, ignorez cet email.

Cordialement,
SOCOM GMAO"""
    send_mail(u["email"],"[GMAO] Réinitialisation de mot de passe",body)
    tok_short = (token[:12] + "…") if token else "(vide)"
    logger.info(f"[RESET] demande pour uid={u['id']} token={tok_short} lien_base={path_suffix or '/'}")
    return jsonify({"ok":True})

@app.route("/api/reset-password/confirm", methods=["POST"])
@limiter.limit("10 per hour")
def confirm_reset():
    d = request.json or {}
    token = d.get("token","")
    new_pw = d.get("password","")
    # Log pour diagnostic
    tok_short = (token[:12] + "…") if token else "(vide)"
    logger.info(f"[RESET confirm] token recu: {tok_short} (len={len(token)})")
    if not token or not new_pw: return jsonify({"error":"Token et mot de passe requis"}),400
    if len(new_pw) < 8: return jsonify({"error":"Mot de passe trop court (8 caractères minimum)"}),400
    db = get_db()
    u = one(db.execute("SELECT * FROM utilisateurs WHERE reset_token=?",(token,)))
    if not u:
        # Cas : le token n'existe plus en base — peut-être déjà utilisé ou demande écrasée
        active = db.execute("SELECT id, nom, LENGTH(reset_token) AS tk_len FROM utilisateurs WHERE reset_token IS NOT NULL AND reset_token != ''").fetchall()
        logger.warning(f"[RESET confirm] token introuvable. Tokens actifs en base: {len(active)} utilisateur(s)")
        return jsonify({"error":"Token invalide ou déjà utilisé. Refaites une demande de réinitialisation."}),400
    # Vérifier expiration
    try:
        expires = datetime.strptime(u["reset_expires"],"%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() > expires:
            logger.info(f"[RESET confirm] token expire pour uid={u['id']}")
            return jsonify({"error":"Lien expiré (valable 1 heure). Refaites une demande de réinitialisation."}),400
    except Exception as e:
        logger.error(f"[RESET confirm] erreur parsing expiration: {e}")
        return jsonify({"error":"Token invalide (données corrompues)"}),400
    # Invalider toutes les sessions existantes (bump token_version)
    new_tv = (u.get("token_version") or 0) + 1
    db.execute("UPDATE utilisateurs SET password=?, reset_token=NULL, reset_expires=NULL, token_version=? WHERE id=?",
               (hash_password(new_pw), new_tv, u["id"]))
    db.commit()
    logger.info(f"[RESET] MDP change pour uid={u['id']} (sessions revoquees)")
    return jsonify({"ok":True})


# ══ MAILS ══
@app.route("/api/mails")
@require_role("admin","manager")
def get_mails():
    db = get_db()
    return jsonify(rows(db.execute(
        "SELECT * FROM mail_log ORDER BY created_at DESC LIMIT 200")))

@app.route("/api/mails/<int:mid>", methods=["DELETE"])
@require_role("admin")
def delete_mail(mid):
    db = get_db()
    db.execute("DELETE FROM mail_log WHERE id=?", (mid,))
    db.commit()
    return jsonify({"ok": True})


# ══ POSTES (organigramme) ══
@app.route("/api/postes")
@require_auth
def get_postes():
    """Liste des postes définis (pour tous les rôles car utilisés dans le form utilisateur)."""
    db = get_db()
    return jsonify(rows(db.execute(
        "SELECT * FROM postes ORDER BY ordre, nom")))

@app.route("/api/postes", methods=["POST"])
@require_role("admin")
def create_poste():
    d = request.json or {}
    nom = (d.get("nom") or "").strip()
    if not nom: return jsonify({"error":"Nom requis"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO postes (nom, ordre) VALUES (?, ?)",
                   (nom, to_int(d.get("ordre")) or 0))
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        log_action(request.user, "CREATE", "poste", new_id, nom)
        return jsonify({"id": new_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/postes/<int:pid>", methods=["PATCH"])
@require_role("admin")
def update_poste(pid):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    if "nom" in d:
        nom = (d.get("nom") or "").strip()
        if not nom: return jsonify({"error":"Nom requis"}), 400
        sets.append("nom=?"); params.append(nom)
    if "ordre" in d:
        sets.append("ordre=?"); params.append(to_int(d.get("ordre")) or 0)
    if not sets: return jsonify({"error":"Rien à modifier"}), 400
    params.append(pid)
    try:
        db.execute(f"UPDATE postes SET {','.join(sets)} WHERE id=?", params)
        db.commit()
        p_info = one(db.execute("SELECT nom FROM postes WHERE id=?", (pid,)))
        log_action(request.user, "UPDATE", "poste", pid, (p_info or {}).get("nom",""))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/postes/<int:pid>", methods=["DELETE"])
@require_role("admin")
def delete_poste(pid):
    db = get_db()
    # Vérifier si poste utilisé
    cnt = one(db.execute("SELECT COUNT(*) AS n FROM utilisateurs WHERE poste_id=?", (pid,)))
    if cnt and cnt["n"] > 0:
        return jsonify({"error": f"Ce poste est attribué à {cnt['n']} utilisateur(s). Retirez-le d'abord."}), 400
    p_info = one(db.execute("SELECT nom FROM postes WHERE id=?", (pid,)))
    label = (p_info or {}).get("nom", f"pid={pid}")
    db.execute("DELETE FROM postes WHERE id=?", (pid,))
    db.commit()
    log_action(request.user, "DELETE", "poste", pid, label)
    return jsonify({"ok": True})


# ══ LOGS (audit) ══
@app.route("/api/logs")
@require_role("admin")
def get_logs():
    """Liste paginée des logs avec filtres.
    
    Params : user_id, action, entity_type, depuis (YYYY-MM-DD), jusqua (YYYY-MM-DD),
             q (recherche libre sur user_nom/action/entity_label/details), limit (default 200, max 1000)
    """
    db = get_db()
    sql = "SELECT * FROM logs WHERE 1=1"
    params = []
    if request.args.get("user_id"):
        sql += " AND user_id=?"; params.append(to_int(request.args.get("user_id")))
    if request.args.get("action"):
        sql += " AND action=?"; params.append(request.args.get("action"))
    if request.args.get("entity_type"):
        sql += " AND entity_type=?"; params.append(request.args.get("entity_type"))
    if request.args.get("depuis"):
        sql += " AND date(created_at) >= date(?)"; params.append(request.args.get("depuis"))
    if request.args.get("jusqua"):
        sql += " AND date(created_at) <= date(?)"; params.append(request.args.get("jusqua"))
    if request.args.get("q"):
        qtxt = f"%{request.args.get('q')}%"
        sql += " AND (user_nom LIKE ? OR action LIKE ? OR entity_label LIKE ? OR details LIKE ?)"
        params += [qtxt, qtxt, qtxt, qtxt]
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except:
        limit = 200
    sql += f" ORDER BY created_at DESC, id DESC LIMIT {limit}"
    return jsonify(rows(db.execute(sql, params)))

@app.route("/api/logs/stats")
@require_role("admin")
def get_logs_stats():
    """Stats pour alimenter les filtres : actions distinctes, entity_types distincts, users distincts."""
    db = get_db()
    actions = [r["action"] for r in rows(db.execute("SELECT DISTINCT action FROM logs WHERE action != '' ORDER BY action"))]
    entity_types = [r["entity_type"] for r in rows(db.execute("SELECT DISTINCT entity_type FROM logs WHERE entity_type != '' ORDER BY entity_type"))]
    users = rows(db.execute("SELECT DISTINCT user_id, user_nom FROM logs WHERE user_id IS NOT NULL ORDER BY user_nom"))
    return jsonify({"actions": actions, "entity_types": entity_types, "users": users})



# ══ TECHNICIENS ASTREINTE ══
@app.route("/api/astreinte/techniciens")
@require_auth
def get_astreinte_techniciens():
    return jsonify(rows(get_db().execute("SELECT * FROM techniciens_astreinte ORDER BY nom")))

@app.route("/api/astreinte/techniciens", methods=["POST"])
@require_role("admin","manager")
def create_astreinte_technicien():
    d=request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db=get_db()
    try:
        db.execute("INSERT INTO techniciens_astreinte (nom,gsm,couleur) VALUES (?,?,?)",
                   (d["nom"],d.get("gsm",""),d.get("couleur","#3b82f6")))
        db.commit()
        return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/astreinte/techniciens/<int:tid>", methods=["PATCH"])
@require_role("admin","manager")
def update_astreinte_technicien(tid):
    d = request.json or {}
    db = get_db()
    n = safe_update(db, "techniciens_astreinte", tid, {k:v for k,v in d.items() if k in ("nom","gsm","couleur","actif")})
    if n == 0: return jsonify({"error":"Rien"}), 400
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/astreinte/techniciens/<int:tid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_astreinte_technicien(tid):
    db=get_db(); db.execute("DELETE FROM techniciens_astreinte WHERE id=?",(tid,)); db.commit()
    return jsonify({"ok":True})

# ══ ASTREINTE ══
@app.route("/api/astreinte/specialites")
@require_auth
def get_astreinte_specialites():
    return jsonify(rows(get_db().execute("SELECT * FROM astreinte_specialites ORDER BY ordre,nom")))

@app.route("/api/astreinte/specialites", methods=["POST"])
@require_role("admin","manager")
def create_astreinte_specialite():
    d=request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db=get_db()
    try:
        db.execute("INSERT INTO astreinte_specialites (nom,description,ordre) VALUES (?,?,?)",
                   (d["nom"],d.get("description",""),d.get("ordre",0)))
        db.commit()
        return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/astreinte/specialites/<int:sid>", methods=["PATCH"])
@require_role("admin","manager")
def update_astreinte_specialite(sid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["nom","description","ordre"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(sid); db.execute(f"UPDATE astreinte_specialites SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/astreinte/specialites/<int:sid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_astreinte_specialite(sid):
    db=get_db(); db.execute("DELETE FROM astreinte_specialites WHERE id=?",(sid,)); db.commit()
    return jsonify({"ok":True})

@app.route("/api/astreinte/planning")
@require_auth
def get_astreinte_planning():
    db=get_db()
    date_from = request.args.get("from","")
    date_to   = request.args.get("to","")
    sql = """SELECT p.*,s.nom AS specialite_nom,s.ordre
             FROM astreinte_planning p
             JOIN astreinte_specialites s ON p.specialite_id=s.id
             WHERE 1=1"""
    params=[]
    if date_from: sql+=" AND p.date>=?"; params.append(date_from)
    if date_to:   sql+=" AND p.date<=?"; params.append(date_to)
    return jsonify(rows(db.execute(sql+" ORDER BY p.date,s.ordre",params)))

@app.route("/api/astreinte/planning/today")
@require_auth
def get_astreinte_today():
    db=get_db()
    td=today()
    return jsonify(rows(db.execute("""SELECT p.*,s.nom AS specialite_nom,s.description,s.ordre
        FROM astreinte_planning p
        JOIN astreinte_specialites s ON p.specialite_id=s.id
        WHERE p.date=? ORDER BY s.ordre""",(td,))))

@app.route("/api/astreinte/planning", methods=["POST"])
@require_role("admin","manager")
def update_astreinte_planning():
    d=request.json or {}
    if not d.get("date") or not d.get("entries"): return jsonify({"error":"date et entries requis"}),400
    db=get_db()
    for entry in d["entries"]:
        sid=to_int(entry.get("specialite_id"))
        tech=entry.get("technicien","")
        if not sid: continue
        db.execute("""INSERT INTO astreinte_planning (date,specialite_id,technicien)
                      VALUES (?,?,?) ON CONFLICT(date,specialite_id) DO UPDATE SET technicien=?""",
                   (d["date"],sid,tech,tech))
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/astreinte/import", methods=["POST"])
@require_role("admin","manager")
def import_astreinte():
    try:
        import openpyxl
        f=request.files.get("file")
        if not f: return jsonify({"error":"Fichier requis"}),400
        wb=openpyxl.load_workbook(f,data_only=True)
        db=get_db()
        # Colonnes du planning
        COLS = [
            (3,"Back-Up Général"),(5,"Back-Up LUXAIRPORT"),(7,"Back-Up SES"),
            (9,"Haute tension"),(11,"Basse tension"),
            (13,"Courant faible (EBRC-BGL-CFL)"),(15,"Courant faible (BIL-SES ASTRA)"),
            (17,"Courant faible (LUXAIRPORT)"),(19,"Courant faible"),
            (21,"Détection incendie BOSCH, NSC"),(23,"Détection incendie ESSER"),
            (25,"HVAC"),(27,"KNX / EIB"),(29,"LITENET/ZUMTOBEL"),
            (31,"DETECTION INCENDIE CEL"),(33,"DETECTION INCENDIE SOLELEC"),
            (35,"DETECTION INCENDIE SCHAUSS"),(37,"HVAC SOCLIMA"),
            (39,"DETECTION INCENDIE GE SOLUTION")
        ]
        # Créer spécialités si nécessaire
        for idx,(col,nom) in enumerate(COLS):
            try:
                db.execute("INSERT OR IGNORE INTO astreinte_specialites (nom,ordre) VALUES (?,?)",(nom,idx))
            except Exception: pass
        db.commit()
        # Récupérer les IDs
        specs={r["nom"]:r["id"] for r in rows(db.execute("SELECT id,nom FROM astreinte_specialites"))}
        count=0
        if "Planning Techniciens" in wb.sheetnames:
            ws=wb["Planning Techniciens"]
            for row in ws.iter_rows(min_row=4,values_only=True):
                date_val=row[0]
                if not date_val: continue
                try:
                    if hasattr(date_val,'strftime'): date_str=date_val.strftime("%Y-%m-%d")
                    else: date_str=str(date_val)[:10]
                except: continue
                for col_idx,nom in COLS:
                    tech=row[col_idx-1] if col_idx-1 < len(row) else None
                    if tech and str(tech).strip() and str(tech).strip()!="nan":
                        sid=specs.get(nom)
                        if sid:
                            db.execute("""INSERT INTO astreinte_planning (date,specialite_id,technicien)
                                VALUES (?,?,?) ON CONFLICT(date,specialite_id) DO UPDATE SET technicien=?""",
                                (date_str,sid,str(tech).strip(),str(tech).strip()))
                            count+=1
        db.commit()
        return jsonify({"ok":True,"imported":count})
    except ImportError: return jsonify({"error":"openpyxl non installe"}),500
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/astreinte/export")
@require_auth
def export_astreinte():
    try:
        import openpyxl
        from openpyxl.styles import Font,PatternFill,Alignment,Border,Side
        db=get_db()
        specs=rows(db.execute("SELECT * FROM astreinte_specialites ORDER BY ordre"))
        planning=rows(db.execute("""SELECT p.*,s.nom AS specialite_nom FROM astreinte_planning p
            JOIN astreinte_specialites s ON p.specialite_id=s.id ORDER BY p.date,s.ordre"""))
        wb=openpyxl.Workbook()
        ws=wb.active; ws.title="Planning Astreinte"
        BF=PatternFill("solid",fgColor="244298"); WF=Font(bold=True,color="FFFFFF")
        # Headers
        headers=["Date"]+[s["nom"] for s in specs]
        ws.append(headers)
        for cell in ws[1]: cell.font=WF; cell.fill=BF; cell.alignment=Alignment(horizontal="center")
        # Data
        from itertools import groupby
        dates=sorted(set(p["date"] for p in planning))
        for date in dates:
            row_data=[date]
            day_data={p["specialite_id"]:p["technicien"] for p in planning if p["date"]==date}
            for s in specs:
                row_data.append(day_data.get(s["id"],""))
            ws.append(row_data)
        for col in ws.columns:
            ws.column_dimensions[col[0].column_letter].width=max(len(str(c.value or "")) for c in col)+4
        buf=io.BytesIO(); wb.save(buf); buf.seek(0)
        return send_file(buf,mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        as_attachment=True,download_name=f"astreinte_export_{today()}.xlsx")
    except Exception as e: return jsonify({"error":str(e)}),500


@app.route("/api/astreinte/import-direct", methods=["POST"])
@require_role("admin")
def import_astreinte_direct():
    """Import direct des données astreinte sans fichier"""
    try:
        d = request.json or {}
        specs_list = d.get("specs", [])
        data = d.get("data", {})
        if not specs_list or not data:
            return jsonify({"error": "specs et data requis"}), 400
        db = get_db()
        # Créer spécialités
        for i, nom in enumerate(specs_list):
            db.execute("INSERT OR IGNORE INTO astreinte_specialites (nom,ordre) VALUES (?,?)", (nom, i))
        db.commit()
        specs = {r["nom"]: r["id"] for r in rows(db.execute("SELECT id,nom FROM astreinte_specialites"))}
        count = 0
        for date_str, day_data in data.items():
            for nom, tech in day_data.items():
                sid = specs.get(nom)
                if sid and tech:
                    db.execute("""INSERT INTO astreinte_planning (date,specialite_id,technicien)
                        VALUES (?,?,?) ON CONFLICT(date,specialite_id) DO UPDATE SET technicien=?""",
                        (date_str, sid, tech, tech))
                    count += 1
        db.commit()
        return jsonify({"ok": True, "imported": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/dashboard/managers")
@require_auth
def get_dashboard_managers():
    """Retourne la liste des managers ayant des projets avec des retards"""
    db = get_db()
    td = today()
    mgrs = rows(db.execute("""
        SELECT DISTINCT u.id, u.nom
        FROM utilisateurs u
        JOIN projets p ON p.manager_id=u.id
        JOIN equipements e ON e.projet_id=p.id
        JOIN interventions i ON i.equipement_id=e.id
        WHERE i.statut NOT IN ('TERMINEE','ANNULEE')
        AND i.date_prevue IS NOT NULL AND date(i.date_prevue) < ?
        ORDER BY u.nom
    """, (td,)))
    return jsonify(mgrs)


@app.route("/api/dashboard/heures")
@require_auth
def get_dashboard_heures():
    """Retourne le total des heures groupées par catégorie :
    - BC (dépannage) : total_heures des intervenants CR sur bons type DEPANNAGE
    - BP (maintenance) : total_heures des intervenants CR sur bons type MAINTENANCE
    - Occupations : total_heures par type d'occupation (une entrée par type)

    Filtre par période via ?debut=YYYY-MM-DD&fin=YYYY-MM-DD (défaut : année courante)
    Filtrage par rôle :
    - admin : toutes les heures
    - manager : uniquement les techs de son équipe (manager_id = lui) + lui-même
    - technicien : uniquement ses propres heures
    """
    u = request.user
    db = get_db()
    today_str = today()
    year = today_str[:4]
    debut = request.args.get("debut") or f"{year}-01-01"
    fin = request.args.get("fin") or f"{year}-12-31"

    # Déterminer la liste des techniciens visibles selon le rôle
    if u["role"] == "admin":
        tech_filter_sql = ""  # pas de filtre
        tech_params = []
    elif u["role"] == "manager":
        team = rows(db.execute("SELECT id FROM utilisateurs WHERE manager_id=?", (u["id"],)))
        tech_ids = [u["id"]] + [t["id"] for t in team]
        if not tech_ids:
            return jsonify({"debut":debut, "fin":fin, "bc":0, "bp":0, "occupations":[]})
        ph = ",".join(["?"] * len(tech_ids))
        tech_filter_sql = f" AND ci.utilisateur_id IN ({ph})"
        tech_params = tech_ids
    else:  # technicien
        tech_filter_sql = " AND ci.utilisateur_id=?"
        tech_params = [u["id"]]

    # BC (dépannage)
    row_bc = one(db.execute(f"""
        SELECT COALESCE(SUM(ci.total_heures),0) AS h
        FROM cr_intervenants ci
        JOIN comptes_rendus cr ON ci.cr_id=cr.id
        JOIN interventions i ON cr.intervention_id=i.id
        WHERE i.type='DEPANNAGE'
          AND (
                (cr.date_intervention BETWEEN ? AND ?)
             OR (NULLIF(ci.date,'') BETWEEN ? AND ?)
          )
          {tech_filter_sql}
    """, [debut, fin, debut, fin] + tech_params))
    heures_bc = float((row_bc or {}).get("h") or 0)

    # BP (maintenance)
    row_bp = one(db.execute(f"""
        SELECT COALESCE(SUM(ci.total_heures),0) AS h
        FROM cr_intervenants ci
        JOIN comptes_rendus cr ON ci.cr_id=cr.id
        JOIN interventions i ON cr.intervention_id=i.id
        WHERE i.type='MAINTENANCE'
          AND (
                (cr.date_intervention BETWEEN ? AND ?)
             OR (NULLIF(ci.date,'') BETWEEN ? AND ?)
          )
          {tech_filter_sql}
    """, [debut, fin, debut, fin] + tech_params))
    heures_bp = float((row_bp or {}).get("h") or 0)

    # Occupations : même logique de filtrage sur technicien_id (occupations.technicien_id)
    # La colonne s'appelle type_id (référence occupation_types)
    # On utilise total_heures directement stocké en DB (pas besoin de recalculer)
    if u["role"] == "admin":
        occ_filter_sql = ""
        occ_params = [debut, fin]
    elif u["role"] == "manager":
        ph_occ = ",".join(["?"] * len(tech_ids))
        occ_filter_sql = f" AND o.technicien_id IN ({ph_occ})"
        occ_params = [debut, fin] + tech_ids
    else:
        occ_filter_sql = " AND o.technicien_id=?"
        occ_params = [debut, fin, u["id"]]

    try:
        occs = rows(db.execute(f"""
            SELECT ot.nom AS type_nom,
                   ot.couleur AS type_couleur,
                   COALESCE(SUM(o.total_heures),0) AS h
            FROM occupations o
            JOIN occupation_types ot ON o.type_id=ot.id
            WHERE o.date BETWEEN ? AND ?
              {occ_filter_sql}
            GROUP BY ot.id, ot.nom, ot.couleur
            HAVING h > 0
            ORDER BY h DESC
        """, occ_params))
    except Exception as ex:
        logger.exception(f"[dashboard/heures] Erreur occupations: {ex}")
        occs = []

    for o in occs:
        o["h"] = round(float(o.get("h") or 0), 2)

    return jsonify({
        "debut": debut,
        "fin": fin,
        "bc": round(heures_bc, 2),
        "bp": round(heures_bp, 2),
        "occupations": occs
    })


# ══ COMPTEURS ══
@app.route("/api/compteur_types")
@require_auth
def get_compteur_types():
    return jsonify(rows(get_db().execute("SELECT * FROM compteur_types ORDER BY nom")))

@app.route("/api/compteur_types", methods=["POST"])
@require_role("admin","manager")
def create_compteur_type():
    d=request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db=get_db()
    try:
        db.execute("INSERT INTO compteur_types (nom,description) VALUES (?,?)",(d["nom"],d.get("description","")))
        db.commit()
        return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/compteur_types/<int:tid>", methods=["PATCH"])
@require_role("admin","manager")
def update_compteur_type(tid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["nom","description"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(tid); db.execute(f"UPDATE compteur_types SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/compteur_types/<int:tid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_compteur_type(tid):
    db=get_db(); db.execute("DELETE FROM compteur_types WHERE id=?",(tid,)); db.commit()
    return jsonify({"ok":True})

@app.route("/api/compteurs")
@require_auth
def get_compteurs():
    eq_id=to_int(request.args.get("equipement_id"))
    if eq_id:
        return jsonify(rows(get_db().execute("""
            SELECT c.*,ct.nom AS type_nom FROM compteurs c
            LEFT JOIN compteur_types ct ON c.type_id=ct.id
            WHERE c.equipement_id=? ORDER BY c.nom""",(eq_id,))))
    return jsonify(rows(get_db().execute("""
        SELECT c.*,ct.nom AS type_nom FROM compteurs c
        LEFT JOIN compteur_types ct ON c.type_id=ct.id ORDER BY c.nom""")))

@app.route("/api/compteurs", methods=["POST"])
@require_role("admin","manager","technicien")
def create_compteur():
    d=request.json or {}
    if not d.get("equipement_id") or not d.get("nom"):
        return jsonify({"error":"equipement_id et nom requis"}),400
    db=get_db()
    db.execute("INSERT INTO compteurs (equipement_id,type_id,nom,numero,unite,localisation) VALUES (?,?,?,?,?,?)",
               (d["equipement_id"],d.get("type_id"),d["nom"],d.get("numero",""),d.get("unite",""),d.get("localisation","")))
    db.commit()
    return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/compteurs/<int:cid>", methods=["PATCH"])
@require_role("admin","manager","technicien")
def update_compteur(cid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["type_id","nom","numero","unite","localisation"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(cid); db.execute(f"UPDATE compteurs SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/compteurs/<int:cid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_compteur(cid):
    db=get_db(); db.execute("DELETE FROM compteurs WHERE id=?",(cid,)); db.commit()
    return jsonify({"ok":True})


@app.route("/api/interventions/<int:iid>/compteurs")
@require_auth
def get_intervention_compteurs(iid):
    db=get_db()
    iv=one(db.execute("SELECT equipement_id FROM interventions WHERE id=?",(iid,)))
    if not iv: return jsonify([])
    return jsonify(rows(db.execute("SELECT c.*,ct.nom AS type_nom FROM compteurs c LEFT JOIN compteur_types ct ON c.type_id=ct.id WHERE c.equipement_id=? ORDER BY c.nom",(iv["equipement_id"],))))

@app.route("/api/releves_compteurs/<int:cr_id>")
@require_auth
def get_releves(cr_id):
    return jsonify(rows(get_db().execute("SELECT r.*,c.nom AS compteur_nom,c.numero,c.unite,c.localisation,ct.nom AS type_nom FROM releves_compteurs r JOIN compteurs c ON r.compteur_id=c.id LEFT JOIN compteur_types ct ON c.type_id=ct.id WHERE r.cr_id=? ORDER BY c.nom",(cr_id,))))

@app.route("/api/releves_compteurs",methods=["POST"])
@require_auth
def save_releves():
    d=request.json or {}
    cr_id=to_int(d.get("cr_id")); releves=d.get("releves",[])
    if not cr_id: return jsonify({"error":"cr_id requis"}),400
    db=get_db()
    for r in releves:
        cid=to_int(r.get("compteur_id"))
        if not cid: continue
        existing=one(db.execute("SELECT id FROM releves_compteurs WHERE cr_id=? AND compteur_id=?",(cr_id,cid)))
        if existing:
            db.execute("UPDATE releves_compteurs SET valeur=?,date_releve=?,notes=? WHERE id=?",(r.get("valeur"),r.get("date_releve",""),r.get("notes",""),existing["id"]))
        else:
            db.execute("INSERT INTO releves_compteurs (cr_id,compteur_id,valeur,date_releve,notes) VALUES (?,?,?,?,?)",(cr_id,cid,r.get("valeur"),r.get("date_releve",""),r.get("notes","")))
    db.commit()
    return jsonify({"ok":True})


# ══ PERSONNALISATION ══
@app.route("/api/personnalisation", methods=["GET"])
@require_auth
def get_personnalisation():
    db = get_db()
    rows_list = rows(db.execute("SELECT cle, valeur FROM parametres_app"))
    return jsonify({r["cle"]: r["valeur"] for r in rows_list})

@app.route("/api/personnalisation", methods=["POST"])
@require_role("admin")
def save_personnalisation():
    d = request.json or {}
    db = get_db()
    for cle, valeur in d.items():
        existing = one(db.execute("SELECT id FROM parametres_app WHERE cle=?", (cle,)))
        if existing:
            db.execute("UPDATE parametres_app SET valeur=? WHERE cle=?", (valeur, cle))
        else:
            db.execute("INSERT INTO parametres_app (cle, valeur) VALUES (?,?)", (cle, valeur))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/personnalisation/logo", methods=["POST"])
@require_role("admin")
def upload_logo():
    d = request.json or {}
    logo_data = d.get("logo", "")
    db = get_db()
    existing = one(db.execute("SELECT id FROM parametres_app WHERE cle='logo'"))
    if existing:
        db.execute("UPDATE parametres_app SET valeur=? WHERE cle='logo'", (logo_data,))
    else:
        db.execute("INSERT INTO parametres_app (cle, valeur) VALUES ('logo',?)", (logo_data,))
    db.commit()
    return jsonify({"ok": True})


# ══ DJU ══
@app.route("/api/dju")
@require_auth
def get_dju():
    """Calcule les DJU chaud et froid depuis Open-Meteo pour un mois donné"""
    import urllib.request, json as json_lib, math
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    ville = request.args.get("ville", "")
    annee = request.args.get("annee", type=int)
    mois = request.args.get("mois", type=int)
    if not lat or not lon or not annee or not mois:
        # Géocoder la ville si lat/lon manquants
        if ville:
            try:
                geo_url = f"https://geocoding-api.open-meteo.com/v1/search?name={urllib.parse.quote(ville)}&count=1&language=fr"
                with urllib.request.urlopen(geo_url, timeout=5) as resp:
                    geo = json_lib.loads(resp.read())
                if geo.get("results"):
                    lat = geo["results"][0]["latitude"]
                    lon = geo["results"][0]["longitude"]
            except Exception as e:
                return jsonify({"error": f"Géocodage échoué: {str(e)}"}), 400
        if not lat or not lon:
            return jsonify({"error": "lat/lon ou ville requis"}), 400
    # Construire les dates du mois
    import calendar
    nb_jours = calendar.monthrange(annee, mois)[1]
    date_debut = f"{annee}-{mois:02d}-01"
    date_fin = f"{annee}-{mois:02d}-{nb_jours:02d}"
    try:
        import urllib.parse
        url = (f"https://archive-api.open-meteo.com/v1/archive?"
               f"latitude={lat}&longitude={lon}"
               f"&start_date={date_debut}&end_date={date_fin}"
               f"&daily=temperature_2m_max,temperature_2m_min"
               f"&timezone=Europe%2FParis")
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json_lib.loads(resp.read())
        t_max = data["daily"]["temperature_2m_max"]
        t_min = data["daily"]["temperature_2m_min"]
        BASE_CHAUD = 18.0
        BASE_FROID = 18.0
        dju_chaud = 0.0
        dju_froid = 0.0
        for tmax, tmin in zip(t_max, t_min):
            if tmax is None or tmin is None:
                continue
            t_moy = (tmax + tmin) / 2
            if t_moy > BASE_CHAUD:
                dju_chaud += t_moy - BASE_CHAUD
            elif t_moy < BASE_FROID:
                dju_froid += BASE_FROID - t_moy
        return jsonify({
            "dju_chaud": round(dju_chaud, 2),
            "dju_froid": round(dju_froid, 2),
            "lat": lat,
            "lon": lon,
            "annee": annee,
            "mois": mois,
            "nb_jours": nb_jours
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/geocode")
@require_auth  
def geocode():
    """Géocode une ville via Open-Meteo"""
    import urllib.request, urllib.parse, json as json_lib
    ville = request.args.get("ville", "")
    cp = request.args.get("cp", "")
    q = cp + " " + ville if cp else ville
    if not q.strip():
        return jsonify({"error": "ville requis"}), 400
    try:
        url = f"https://geocoding-api.open-meteo.com/v1/search?name={urllib.parse.quote(q.strip())}&count=1&language=fr"
        with urllib.request.urlopen(url, timeout=5) as resp:
            geo = json_lib.loads(resp.read())
        if geo.get("results"):
            r = geo["results"][0]
            return jsonify({"lat": r["latitude"], "lon": r["longitude"], "nom": r.get("name",""), "pays": r.get("country","")})
        return jsonify({"error": "Ville non trouvée"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══ GRAPHIQUES CONFIG ══
@app.route("/api/graphiques/<int:projet_id>")
@require_auth
def get_graphiques(projet_id):
    import json as _json
    rows_g = rows(get_db().execute("SELECT * FROM graphiques_config WHERE projet_id=? ORDER BY ordre,id",(projet_id,)))
    for g in rows_g:
        try: g["series"] = _json.loads(g["series"])
        except: g["series"] = []
    return jsonify(rows_g)

@app.route("/api/graphiques", methods=["POST"])
@require_role("admin","manager")
def create_graphique():
    import json as _json
    d = request.json or {}
    if not d.get("projet_id"): return jsonify({"error":"projet_id requis"}),400
    db = get_db()
    db.execute("INSERT INTO graphiques_config (projet_id,titre,ordre,series,comparaison) VALUES (?,?,?,?,?)",
               (d["projet_id"],d.get("titre","Graphique"),d.get("ordre",0),_json.dumps(d.get("series",[])),d.get("comparaison",0)))
    db.commit()
    return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/graphiques/<int:gid>", methods=["PATCH"])
@require_role("admin","manager")
def update_graphique(gid):
    import json as _json
    d = request.json or {}; db = get_db()
    sets,params = [],[]
    if "titre" in d: sets.append("titre=?"); params.append(d["titre"])
    if "ordre" in d: sets.append("ordre=?"); params.append(d["ordre"])
    if "series" in d: sets.append("series=?"); params.append(_json.dumps(d["series"]))
    if "comparaison" in d: sets.append("comparaison=?"); params.append(d["comparaison"])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(gid)
    db.execute(f"UPDATE graphiques_config SET {chr(44).join(sets)} WHERE id=?",params)
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/graphiques/<int:gid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_graphique(gid):
    db = get_db()
    db.execute("DELETE FROM graphiques_config WHERE id=?",(gid,))
    db.commit()
    return jsonify({"ok":True})


# ══ ANALYSES RAPPORT ══
@app.route("/api/analyses/<int:projet_id>/<int:annee>")
@require_auth
def get_analyses(projet_id, annee):
    rows_a = rows(get_db().execute(
        "SELECT * FROM analyses_rapport WHERE projet_id=? AND annee=?",
        (projet_id, annee)))
    return jsonify({r["type_analyse"]: r["texte"] for r in rows_a})

@app.route("/api/analyses/<int:projet_id>/<int:annee>", methods=["POST"])
@require_auth
def save_analyse(projet_id, annee):
    d = request.json or {}
    type_analyse = d.get("type_analyse","")
    texte = d.get("texte","")
    if not type_analyse: return jsonify({"error":"type_analyse requis"}),400
    db = get_db()
    db.execute("""INSERT INTO analyses_rapport (projet_id,annee,type_analyse,texte,updated_at)
        VALUES (?,?,?,?,datetime('now'))
        ON CONFLICT(projet_id,annee,type_analyse)
        DO UPDATE SET texte=excluded.texte, updated_at=excluded.updated_at""",
        (projet_id, annee, type_analyse, texte))
    db.commit()
    return jsonify({"ok": True})


# ══ PARAMETRES RAPPORT ══
@app.route("/api/parametres_rapport/<int:projet_id>/<int:annee>")
@require_auth
def get_parametres_rapport(projet_id, annee):
    rows_p = rows(get_db().execute(
        "SELECT * FROM parametres_rapport WHERE projet_id=? AND annee=? ORDER BY chapitre,ordre,id",
        (projet_id, annee)))
    result = {}
    for r in rows_p:
        ch = r["chapitre"]
        if ch not in result: result[ch] = []
        result[ch].append({"id":r["id"],"parametre":r["parametre"],"valeur":r["valeur"],"ordre":r["ordre"]})
    return jsonify(result)

@app.route("/api/parametres_rapport", methods=["POST"])
@require_auth
def create_parametre_rapport():
    d = request.json or {}
    if not d.get("projet_id") or not d.get("chapitre"):
        return jsonify({"error":"projet_id et chapitre requis"}),400
    db = get_db()
    db.execute("INSERT INTO parametres_rapport (projet_id,annee,chapitre,parametre,valeur,ordre) VALUES (?,?,?,?,?,?)",
               (d["projet_id"],d.get("annee",0),d["chapitre"],d.get("parametre",""),d.get("valeur",""),d.get("ordre",0)))
    db.commit()
    return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/parametres_rapport/<int:rid>", methods=["PATCH"])
@require_auth
def update_parametre_rapport(rid):
    d = request.json or {}; db = get_db(); sets,params=[],[]
    for f in ["parametre","valeur","ordre"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(rid)
    db.execute(f"UPDATE parametres_rapport SET {chr(44).join(sets)} WHERE id=?",params)
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/parametres_rapport/<int:rid>", methods=["DELETE"])
@require_auth
def delete_parametre_rapport(rid):
    db = get_db()
    db.execute("DELETE FROM parametres_rapport WHERE id=?",(rid,))
    db.commit()
    return jsonify({"ok":True})


# ══ RAPPORT ENERGETIQUE PDF COMPLET ══
@app.route("/api/rapport-energie/<int:projet_id>/pdf-complet", methods=["POST"])
@require_auth
def generate_rapport_complet(projet_id):
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from matplotlib.patches import FancyBboxPatch, Circle, Wedge
        import numpy as np
        from reportlab.lib.pagesizes import landscape, A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, PageBreak, HRFlowable, KeepTogether
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.pdfgen import canvas as rl_canvas
        from reportlab.lib.utils import ImageReader
        import base64, io, calendar, re as _re
        from datetime import datetime
        from itertools import groupby

        db = get_db()
        proj = one(db.execute("SELECT * FROM projets WHERE id=?", (projet_id,)))
        if not proj: return jsonify({"error":"Projet non trouve"}),404
        data = request.json or {}
        annee = int(data.get("annee", datetime.now().year))
        PAGE_W, PAGE_H = landscape(A4)
        BLUE = colors.HexColor("#213e9a")  # SOCOM Blue
        ACCENT = colors.HexColor("#213e9a")  # SOCOM Blue
        LIGHT = colors.HexColor("#e8ecf8")  # SOCOM Blue light
        BORDER = colors.HexColor("#c5cef0")  # SOCOM Blue border
        buf = io.BytesIO()
        buf_garde = io.BytesIO()
        buf_data = io.BytesIO()
        proj_nom = proj.get("nom","") or ""
        proj_loc = (str(proj.get("ville",""))+" "+str(proj.get("code_postal",""))).strip() if proj.get("ville") else ""

        # ═══════════════════════════════════════
        # PAGE DE GARDE (canvas dans buf_garde)
        # ═══════════════════════════════════════
        cv = rl_canvas.Canvas(buf_garde, pagesize=landscape(A4))
        SOCOM_BLUE = "#213e9a"
        SOCOM_DARK = "#0d1728"

        # ══ FOND BLANC ══
        cv.setFillColor(colors.white)
        cv.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

        # ══ IMAGE DROITE ══
        import PIL.Image as PILImage
        import numpy as np2
        try:
            _img_path = "/var/www/gmao/rapport_cover.jpg"
            import os
            if not os.path.exists(_img_path):
                raise FileNotFoundError
            _pimg = PILImage.open(_img_path).convert("RGB")
        except Exception:
            _pimg = None

        if _pimg:
            _iw, _ih = _pimg.size
            _iz_x = PAGE_W * 0.40; _iz_w = PAGE_W * 0.60; _iz_h = PAGE_H
            _rz = _iz_w / _iz_h; _ri = _iw / _ih
            if _ri > _rz:
                _nw = int(_ih * _rz); _off = (_iw - _nw) // 2
                _ic = _pimg.crop((_off, 0, _off + _nw, _ih))
            else:
                _nh = int(_iw / _rz); _off = (_ih - _nh) // 2
                _ic = _pimg.crop((0, _off, _iw, _off + _nh))
            _ic = _ic.resize((int(_iz_w * 2), int(_iz_h * 2)), PILImage.LANCZOS)
            _ib = io.BytesIO(); _ic.save(_ib, format="JPEG", quality=90); _ib.seek(0)
            cv.drawImage(ImageReader(_ib), _iz_x, 0, width=_iz_w, height=_iz_h, preserveAspectRatio=False)
            # Fondu blanc
            _fw = 130
            _fp = np2.zeros((int(_iz_h * 3), _fw, 4), dtype=np2.uint8)
            for _x in range(_fw):
                _a = int(255 * (1 - _x/_fw) ** 1.6)
                _fp[:, _x, :] = [255, 255, 255, _a]
            _fi = PILImage.fromarray(_fp, "RGBA")
            _fb = io.BytesIO(); _fi.save(_fb, format="PNG"); _fb.seek(0)
            cv.drawImage(ImageReader(_fb), _iz_x - 5, 0, width=_fw/3, height=_iz_h, mask="auto")

        # ══ ZONE BLANCHE GAUCHE ══
        cv.setFillColor(colors.white)
        cv.rect(0, 0, PAGE_W * 0.415, PAGE_H, fill=1, stroke=0)
        cv.setFillColor(colors.HexColor(SOCOM_BLUE))
        cv.rect(PAGE_W * 0.415, 0, 3, PAGE_H, fill=1, stroke=0)
        cv.rect(0, PAGE_H - 5, PAGE_W * 0.415, 5, fill=1, stroke=0)

        # ══ LOGO SOCOM TEXTE ══
        try:
            html_c2 = open("/var/www/gmao/index.html").read()
            import re as _re2
            _matches = list(_re2.finditer(r'src="data:image/([^;]+);base64,([^"]{100,})"', html_c2))
            import base64 as _b64
            # Image 1 = logo texte 650x148
            if len(_matches) >= 2:
                _logo_bytes = _b64.b64decode(_matches[1].group(2))
                _limg = ImageReader(io.BytesIO(_logo_bytes))
            else:
                _limg = ImageReader(io.BytesIO(_b64.b64decode(_matches[0].group(2))))
            _lw = 200; _lh = _lw * 148/650
            cv.drawImage(_limg, 36, PAGE_H - _lh - 28, width=_lw, height=_lh)
        except Exception: pass

        # Ligne sous logo
        cv.setStrokeColor(colors.HexColor("#e2e8f0"))
        cv.setLineWidth(0.8)
        cv.line(36, PAGE_H - 80, PAGE_W * 0.40, PAGE_H - 80)

        # ══ TITRE ══
        cv.setFillColor(colors.HexColor(SOCOM_DARK))
        cv.setFont("Helvetica-Bold", 36)
        cv.drawString(36, PAGE_H * 0.535, "SUIVI")
        cv.setFont("Helvetica-Bold", 36)
        cv.drawString(36, PAGE_H * 0.455, "ENERGETIQUE")

        # Ligne accent
        cv.setStrokeColor(colors.HexColor(SOCOM_BLUE))
        cv.setLineWidth(3)
        cv.line(36, PAGE_H * 0.432, 220, PAGE_H * 0.432)

        # Sous-titre
        cv.setFillColor(colors.HexColor("#64748b"))
        cv.setFont("Helvetica", 10)
        cv.drawString(36, PAGE_H * 0.395, "Analyse & Comparaison annuelle")

        # Séparateur
        cv.setStrokeColor(colors.HexColor("#e2e8f0"))
        cv.setLineWidth(0.8)
        cv.line(36, PAGE_H * 0.368, PAGE_W * 0.38, PAGE_H * 0.368)

        # ══ INFOS PROJET ══
        cv.setFillColor(colors.HexColor(SOCOM_DARK))
        cv.setFont("Helvetica-Bold", 18)
        cv.drawString(36, PAGE_H * 0.330, proj_nom)
        cv.setFillColor(colors.HexColor("#64748b"))
        cv.setFont("Helvetica", 10)
        if proj_loc: cv.drawString(36, PAGE_H * 0.290, proj_loc)
        cv.drawString(36, PAGE_H * 0.255, "Annee "+str(annee-1)+" vs "+str(annee))

        # ══ PIED DE PAGE ══
        cv.setFillColor(colors.HexColor(SOCOM_BLUE))
        cv.rect(0, 0, PAGE_W * 0.415, 22, fill=1, stroke=0)
        cv.setFillColor(colors.HexColor("#1a3180"))
        cv.rect(0, 0, 4, 22, fill=1, stroke=0)
        cv.setFillColor(colors.white)
        cv.setFont("Helvetica-Bold", 7.5)
        cv.drawString(12, 7, "SOCOM - Maintenance Multi-Techniques")
        cv.setFillColor(colors.HexColor("#64748b"))
        cv.setFont("Helvetica", 7.5)
        cv.drawString(PAGE_W-155, 7, "Genere le "+datetime.now().strftime("%d/%m/%Y"))

        cv.showPage()
        # Finaliser la page de garde
        cv.save()

        # ═══════════════════════════════════════
        # PAGES DE DONNÉES
        # ═══════════════════════════════════════
        styles2=getSampleStyleSheet()
        title_s=ParagraphStyle("T",parent=styles2["Heading1"],fontSize=13,textColor=BLUE,spaceBefore=0,spaceAfter=8)
        section_s=ParagraphStyle("S",parent=styles2["Heading2"],fontSize=10,textColor=ACCENT,spaceBefore=10,spaceAfter=4)
        normal_s=ParagraphStyle("N",parent=styles2["Normal"],fontSize=8,spaceAfter=4)
        cell_s=ParagraphStyle("C",parent=styles2["Normal"],fontSize=7,wordWrap="CJK")

        def mk_cell(txt):
            return Paragraph(str(txt) if txt else "—", cell_s)

        def mk_table(data_r, total_w=None):
            # Largeurs adaptatives : calculer max chars par colonne
            if not data_r or len(data_r)<1: return Spacer(1,1)
            n_cols=len(data_r[0])
            avail=total_w or (PAGE_W-2.4*cm)
            # Largeur min par col selon contenu
            col_chars=[0]*n_cols
            for row in data_r:
                for j,cell in enumerate(row):
                    txt=str(cell) if cell else ""
                    col_chars[j]=max(col_chars[j],len(txt))
            total_chars=sum(col_chars) or 1
            cws=[max(1.5*cm, min(6*cm, avail*col_chars[j]/total_chars)) for j in range(n_cols)]
            # Normaliser pour que la somme = avail
            s_cws=sum(cws)
            cws=[w*avail/s_cws for w in cws]
            # Wrapper les cellules en Paragraph
            wrapped=[]
            for i3,row in enumerate(data_r):
                wrapped.append([mk_cell(cell) if i3>0 else Paragraph(str(cell) if cell else "",
                    ParagraphStyle("H",parent=styles2["Normal"],fontSize=7,textColor=colors.white,fontName="Helvetica-Bold")) for cell in row])
            t=Table(wrapped,colWidths=cws,repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),BLUE),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("GRID",(0,0),(-1,-1),0.5,BORDER),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,LIGHT]),
                ("ALIGN",(0,0),(-1,-1),"CENTER"),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                ("PADDING",(0,0),(-1,-1),4),
            ]))
            return t

        # Charger données
        equips=rows(db.execute("SELECT e.* FROM equipements e WHERE e.projet_id=? AND e.type_technique='Compteurs'",(projet_id,)))
        story_p=[]

        for eq in equips:
            eq["compteurs"]=rows(db.execute("SELECT c.*,ct.nom AS type_nom FROM compteurs c LEFT JOIN compteur_types ct ON c.type_id=ct.id WHERE c.equipement_id=? ORDER BY c.nom",(eq["id"],)))
            ivs=rows(db.execute("SELECT * FROM interventions WHERE equipement_id=? ORDER BY date_prevue",(eq["id"],)))
            cols_d=[]
            for iv in ivs:
                dp=str(iv.get("date_prevue","") or "")
                if not dp or str(dp)[:4] not in [str(annee),str(annee-1)]: continue
                for cr in rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=?",(iv["id"],))):
                    cr["releves"]=rows(db.execute("SELECT r.*,c.nom AS cnom FROM releves_compteurs r JOIN compteurs c ON r.compteur_id=c.id WHERE r.cr_id=?",(cr["id"],)))
                    cr["numero_bt"]=str(iv.get("numero","") or ""); cr["date_planif"]=dp
                    cols_d.append(cr)
            cols_d.sort(key=lambda x:str(x.get("date_planif","")))
            eq["cols"]=cols_d[:12]
            if not eq["compteurs"] or not eq["cols"]: continue

            story_p.append(Paragraph("Equipement : "+str(eq.get("designation","")),title_s))
            if eq.get("localisation"): story_p.append(Paragraph("Localisation : "+str(eq["localisation"]),normal_s))
            story_p.append(HRFlowable(width="100%",thickness=1,color=ACCENT,spaceAfter=6))
            cpts=eq["compteurs"]; cols=eq["cols"]

            def bt_lbl(c4): return str(c4.get("numero_bt",""))+" "+str(c4.get("date_planif",""))[:10]

            # ── Relevés ──
            story_p.append(Paragraph("Releves",section_s))
            hdrs=["Type","Compteur","Localisation","Unite"]+[bt_lbl(c4) for c4 in cols]
            rrows=[hdrs]
            for cpt in cpts:
                row=[cpt.get("type_nom","—"),cpt.get("nom","—"),cpt.get("localisation","—"),cpt.get("unite","—")]
                for c4 in cols:
                    r4=next((r for r in c4.get("releves",[]) if r["compteur_id"]==cpt["id"]),None)
                    row.append(str(round(r4["valeur"],1)) if r4 and r4.get("valeur") is not None else "—")
                rrows.append(row)
            story_p.append(mk_table(rrows)); story_p.append(Spacer(1,8))

            # ── Consommations Brutes ──
            if len(cols)>1:
                story_p.append(Paragraph("Consommations Brutes",section_s))
                hdrs2=["Type","Compteur","Localisation","Unite"]+[bt_lbl(cols[i4]) for i4 in range(1,len(cols))]
                cbrows=[hdrs2]
                for cpt in cpts:
                    row=[cpt.get("type_nom","—"),cpt.get("nom","—"),cpt.get("localisation","—"),cpt.get("unite","—")]
                    for i4 in range(1,len(cols)):
                        rp4=next((r for r in cols[i4-1].get("releves",[]) if r["compteur_id"]==cpt["id"]),None)
                        rc4=next((r for r in cols[i4].get("releves",[]) if r["compteur_id"]==cpt["id"]),None)
                        if rp4 and rc4 and rp4.get("valeur") is not None and rc4.get("valeur") is not None:
                            row.append(str(round(rc4["valeur"]-rp4["valeur"],2)))
                        else: row.append("—")
                    cbrows.append(row)
                story_p.append(mk_table(cbrows)); story_p.append(Spacer(1,8))

            # ── Consommations Corrigées ──
            if len(cols)>1:
                story_p.append(Paragraph("Consommations Corrigees",section_s))
                hdrs3=["Type","Compteur","Localisation","Unite"]+[bt_lbl(cols[i4-1]) for i4 in range(1,len(cols))]
                ccrows=[hdrs3]
                for cpt in cpts:
                    row=[cpt.get("type_nom","—"),cpt.get("nom","—"),cpt.get("localisation","—"),cpt.get("unite","—")]
                    for i4 in range(1,len(cols)):
                        rp4=next((r for r in cols[i4-1].get("releves",[]) if r["compteur_id"]==cpt["id"]),None)
                        rc4=next((r for r in cols[i4].get("releves",[]) if r["compteur_id"]==cpt["id"]),None)
                        dp4s=str(cols[i4-1].get("date_planif","") or ""); dc4s=str(cols[i4].get("date_planif","") or "")
                        if rp4 and rc4 and rp4.get("valeur") is not None and rc4.get("valeur") is not None and dp4s and dc4s:
                            try:
                                dp4=datetime.strptime(dp4s[:10],"%Y-%m-%d"); dc4_=datetime.strptime(dc4s[:10],"%Y-%m-%d")
                                nj=abs((dc4_-dp4).days); njm=calendar.monthrange(dp4.year,dp4.month)[1]
                                row.append(str(round((rc4["valeur"]-rp4["valeur"])/nj*njm,2)) if nj>0 else "—")
                            except: row.append("—")
                        else: row.append("—")
                    ccrows.append(row)
                story_p.append(mk_table(ccrows))
            story_p.append(PageBreak())

        # ── Graphiques matplotlib (recalculés côté serveur) ──
        graphiques=rows(db.execute("SELECT * FROM graphiques_config WHERE projet_id=? ORDER BY ordre,id",(projet_id,)))
        import json as _json2
        if graphiques:
            story_p.append(Paragraph("Graphiques",title_s))
            story_p.append(HRFlowable(width="100%",thickness=1,color=ACCENT,spaceAfter=8))
            story_p.append(PageBreak())
            # Charger données compteurs pour graphiques
            equips_g=rows(db.execute("SELECT e.* FROM equipements e WHERE e.projet_id=? AND e.type_technique='Compteurs'",(projet_id,)))
            cpt_data={}
            for eq in equips_g:
                cpts_g=rows(db.execute("SELECT c.*,ct.nom AS type_nom FROM compteurs c LEFT JOIN compteur_types ct ON c.type_id=ct.id WHERE c.equipement_id=?",(eq["id"],)))
                ivs_g=rows(db.execute("SELECT * FROM interventions WHERE equipement_id=? ORDER BY date_prevue",(eq["id"],)))
                cols_g=[]
                for iv in ivs_g:
                    dp=str(iv.get("date_prevue","") or "")
                    if not dp or str(dp)[:4] not in [str(annee),str(annee-1)]: continue
                    for cr in rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=?",(iv["id"],))):
                        cr["releves"]=rows(db.execute("SELECT r.*,c.nom AS cnom FROM releves_compteurs r JOIN compteurs c ON r.compteur_id=c.id WHERE r.cr_id=?",(cr["id"],)))
                        cr["numero_bt"]=str(iv.get("numero","") or ""); cr["date_planif"]=dp
                        cols_g.append(cr)
                cols_g.sort(key=lambda x:str(x.get("date_planif","")))
                cols_g=cols_g[:12]
                for cpt in cpts_g:
                    cpt_data[cpt["id"]]={"nom":cpt["nom"],"unite":cpt.get("unite",""),"pts":[]}
                    for i4 in range(1,len(cols_g)):
                        rp4=next((r for r in cols_g[i4-1].get("releves",[]) if r["compteur_id"]==cpt["id"]),None)
                        rc4=next((r for r in cols_g[i4].get("releves",[]) if r["compteur_id"]==cpt["id"]),None)
                        dp4s=str(cols_g[i4-1].get("date_planif","") or ""); dc4s=str(cols_g[i4].get("date_planif","") or "")
                        if rp4 and rc4 and rp4.get("valeur") is not None and rc4.get("valeur") is not None and dp4s and dc4s:
                            try:
                                dp4=datetime.strptime(dp4s[:10],"%Y-%m-%d"); dc4_=datetime.strptime(dc4s[:10],"%Y-%m-%d")
                                nj=abs((dc4_-dp4).days); njm=calendar.monthrange(dp4.year,dp4.month)[1]
                                val=round((rc4["valeur"]-rp4["valeur"])/nj*njm,2) if nj>0 else None
                                lbl=dp4s[:7]
                                cpt_data[cpt["id"]]["pts"].append({"label":lbl,"value":val})
                            except Exception: pass

            COLORS_G=["#3b82f6","#ef4444","#22c55e","#f59e0b","#8b5cf6","#14b8a6","#f97316"]
            GRAPH_W = (PAGE_W - 2.4*cm) * 0.75  # Largeur -25%
            GRAPH_H = PAGE_H * 0.62 * 0.75   # Hauteur -25%

            for g5 in graphiques:
                try:
                    series5=_json2.loads(g5.get("series","[]"))
                    if not series5: continue
                    titre5 = str(g5.get("titre","Graphique"))
                    types5=[s.get("type","histogramme") for s in series5]
                    has_dual=len(set(types5))>1 and len(series5)>1

                    fig5,ax5=plt.subplots(figsize=(11,5),facecolor="white")
                    ax5.set_facecolor("#f8fafc")
                    ax5_r=ax5.twinx() if has_dual else None
                    has_data=False

                    for si5,serie5 in enumerate(series5):
                        cid5=serie5.get("compteur_id")
                        col5=COLORS_G[si5%len(COLORS_G)]
                        ax_use=ax5_r if (has_dual and si5>0) else ax5
                        pts5=[]
                        # Chercher par id int ou string
                        cid5_key=None
                        for k in cpt_data.keys():
                            if str(k)==str(cid5): cid5_key=k; break
                        if cid5_key is not None:
                            pts5=cpt_data[cid5_key]["pts"]
                        if not pts5: continue
                        lbls5=[p["label"] for p in pts5 if p["value"] is not None]
                        vals5=[p["value"] for p in pts5 if p["value"] is not None]
                        if not lbls5: continue
                        lbl5=str(serie5.get("label","") or serie5.get("nom_compteur","") or "Serie ")+str(si5+1)
                        t5=serie5.get("type","histogramme")
                        x5=range(len(lbls5))
                        if t5=="courbe":
                            ax_use.plot(x5,vals5,"o-",color=col5,lw=2.5,ms=6,label=lbl5)
                        elif t5=="histogramme_empile":
                            ax_use.bar(x5,vals5,color=col5,alpha=0.78,label=lbl5)
                        else:
                            offset=si5*0.35 if not has_dual else 0
                            ax_use.bar([x+offset for x in x5],vals5,width=0.35,color=col5,alpha=0.78,label=lbl5)
                        ax5.set_xticks(range(len(lbls5))); ax5.set_xticklabels(lbls5,rotation=30,ha="right",fontsize=8)
                        has_data=True

                    if has_data:
                        ax5.set_title(titre5,fontsize=12,fontweight="bold",color="#0d1b2a",pad=12)
                        ax5.grid(axis="y",alpha=0.3,linestyle="--",color="#e2e8f0")
                        ax5.spines["top"].set_visible(False); ax5.spines["right"].set_visible(False)
                        ax5.spines["left"].set_color("#e2e8f0"); ax5.spines["bottom"].set_color("#e2e8f0")
                        ax5.tick_params(colors="#64748b",labelsize=8)
                        handles5,labels5_=ax5.get_legend_handles_labels()
                        if ax5_r:
                            h2,l2=ax5_r.get_legend_handles_labels()
                            handles5+=h2; labels5_+=l2
                            ax5_r.spines["top"].set_visible(False)
                            ax5_r.tick_params(colors="#64748b",labelsize=8)
                        if handles5: ax5.legend(handles5,labels5_,fontsize=9,loc="upper right",framealpha=0.9,edgecolor="#e2e8f0")
                        plt.tight_layout(pad=1.5)
                        gi=io.BytesIO()
                        plt.savefig(gi,format="png",dpi=150,bbox_inches="tight",facecolor="white",edgecolor="none")
                        gi.seek(0)
                        # Un graphique par page, centré, titre et graphique ensemble
                        story_p.append(KeepTogether([
                            Spacer(1, (PAGE_H - 2.6*cm - GRAPH_H - 40) / 2),  # Centrage vertical
                            Paragraph(titre5, ParagraphStyle("GT",parent=styles2["Heading2"],fontSize=14,textColor=BLUE,spaceAfter=12,alignment=1)),
                            RLImage(gi, width=GRAPH_W, height=GRAPH_H),
                            Spacer(1,10),
                        ]))
                        story_p.append(PageBreak())
                    plt.close(fig5)
                except Exception as eg:
                    import traceback; pass

                # ── Analyses ──
        analyses=rows(db.execute("SELECT * FROM analyses_rapport WHERE projet_id=? AND annee=?",(projet_id,annee)))
        if analyses and any(a.get("texte") for a in analyses):
            story_p.append(Paragraph("Analyses",title_s))
            story_p.append(HRFlowable(width="100%",thickness=1,color=ACCENT,spaceAfter=6))
            for a2 in analyses:
                if a2.get("texte"):
                    story_p.append(Paragraph(str(a2.get("type_analyse","")),section_s))
                    story_p.append(Paragraph(str(a2["texte"]),normal_s)); story_p.append(Spacer(1,4))
            story_p.append(PageBreak())

        # ── Paramètres ──
        params=rows(db.execute("SELECT * FROM parametres_rapport WHERE projet_id=? AND annee=? ORDER BY chapitre,ordre",(projet_id,annee)))
        if params:
            story_p.append(Paragraph("Parametres",title_s))
            story_p.append(HRFlowable(width="100%",thickness=1,color=ACCENT,spaceAfter=6))
            for ch3,items3 in groupby(params,key=lambda x:x["chapitre"]):
                story_p.append(Paragraph(str(ch3),section_s))
                pr=[["Parametre","Valeur"]]
                for it in items3:
                    if it.get("parametre") or it.get("valeur"):
                        pr.append([str(it.get("parametre","")),str(it.get("valeur",""))])
                if len(pr)>1: story_p.append(mk_table(pr))
                story_p.append(Spacer(1,6))

        def on_pg(c6,doc):
            c6.saveState()
            c6.setFillColor(BLUE); c6.rect(0,PAGE_H-26,PAGE_W,26,fill=1,stroke=0)
            c6.setFillColor(colors.white); c6.setFont("Helvetica-Bold",9)
            c6.drawString(16,PAGE_H-17,"SUIVI ENERGETIQUE - "+proj_nom)
            c6.setFont("Helvetica",8); c6.drawRightString(PAGE_W-16,PAGE_H-17,"Annee "+str(annee))
            c6.setFillColor(colors.HexColor("#f8fafc")); c6.rect(0,0,PAGE_W,18,fill=1,stroke=0)
            c6.setFillColor(ACCENT); c6.rect(0,0,4,18,fill=1,stroke=0)
            c6.setFillColor(colors.HexColor("#64748b")); c6.setFont("Helvetica",7)
            c6.drawString(12,5,"SOCOM"); c6.drawRightString(PAGE_W-12,5,"Page "+str(doc.page))
            c6.restoreState()

        if story_p:
            doc=SimpleDocTemplate(buf_data,pagesize=landscape(A4),leftMargin=1.2*cm,rightMargin=1.2*cm,topMargin=1.8*cm,bottomMargin=1.2*cm)
            doc.build(story_p,onFirstPage=on_pg,onLaterPages=on_pg)

        # ═══════════════════════════════════════
        # FUSION : page de garde + pages de données
        # ═══════════════════════════════════════
        from pypdf import PdfWriter, PdfReader
        writer = PdfWriter()
        # Page de garde
        buf_garde.seek(0)
        try:
            for page in PdfReader(buf_garde).pages:
                writer.add_page(page)
        except Exception: pass
        # Pages de données (si existantes)
        if story_p:
            buf_data.seek(0)
            try:
                for page in PdfReader(buf_data).pages:
                    writer.add_page(page)
            except Exception: pass
        writer.write(buf)
        buf.seek(0)
        fname="rapport_energie_"+proj_nom.replace(" ","_")+"_"+str(annee)+".pdf"
        return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=fname)

    except Exception as e:
        import traceback
        return jsonify({"error":str(e),"trace":traceback.format_exc()}),500


@app.route("/api/login",methods=["POST"])
@limiter.limit("10 per minute")
def login():
    d = request.json or {}
    email = (d.get("email","") or "").strip().lower()
    pw    = d.get("password","") or ""
    db = get_db()
    u = one(db.execute("SELECT * FROM utilisateurs WHERE lower(email)=? AND actif=1", (email,)))
    if not u or not verify_password(pw, u["password"]):
        # Délai constant pour freiner timing attacks
        time.sleep(0.3)
        logger.warning(f"[LOGIN] echec pour {email} depuis {request.remote_addr}")
        return jsonify({"error":"Email ou mot de passe incorrect"}), 401

    # Rehash automatique vers bcrypt si MDP legacy SHA-256
    if needs_rehash(u["password"]):
        try:
            new_hash = hash_password(pw)
            db.execute("UPDATE utilisateurs SET password=? WHERE id=?", (new_hash, u["id"]))
            db.commit()
            u["password"] = new_hash
            logger.info(f"[REHASH] MDP migre vers bcrypt pour uid={u['id']}")
        except Exception as e:
            logger.warning(f"[REHASH] echec uid={u['id']}: {e}")

    token = make_token(u)
    logger.info(f"[LOGIN] succes uid={u['id']} role={u['role']} depuis {request.remote_addr}")
    log_action(u, "LOGIN", entity_type="utilisateur", entity_id=u["id"], entity_label=u["nom"],
               details=f"depuis {request.remote_addr}")
    return jsonify({
        "token": token,
        "user": {"id": u["id"], "nom": u["nom"], "email": u["email"], "role": u["role"]}
    })

# ══ UTILISATEURS ══
def _techniques_to_list(csv_val):
    """Normalise la valeur techniques (CSV) en liste d'abord en évitant doublons et vides."""
    if not csv_val:
        return []
    parts = [x.strip() for x in str(csv_val).split(",")]
    seen = set(); out = []
    for p in parts:
        if p and p not in seen:
            seen.add(p); out.append(p)
    return out

def _techniques_from_body(val):
    """Accepte liste, CSV, ou None. Retourne un CSV propre."""
    if val is None:
        return ""
    if isinstance(val, list):
        items = val
    else:
        items = [x.strip() for x in str(val).split(",")]
    seen = set(); out = []
    for it in items:
        it = str(it).strip()
        if it and it not in seen:
            seen.add(it); out.append(it)
    return ",".join(out)

@app.route("/api/utilisateurs")
@require_auth
def get_utilisateurs():
    result = rows(get_db().execute("""
        SELECT u.id, u.nom, u.email, u.role, u.actif, u.matricule, u.manager_id, u.techniques,
               u.poste_id, u.superieur_id,
               m.nom AS manager_nom,
               p.nom AS poste_nom,
               s.nom AS superieur_nom
        FROM utilisateurs u
        LEFT JOIN utilisateurs m ON u.manager_id = m.id
        LEFT JOIN postes p ON u.poste_id = p.id
        LEFT JOIN utilisateurs s ON u.superieur_id = s.id
        ORDER BY u.nom
    """))
    # Convertir le CSV en liste pour le frontend
    for r in result:
        r["techniques_list"] = _techniques_to_list(r.get("techniques"))
    return jsonify(result)

@app.route("/api/type_techniques")
@require_auth
def get_type_techniques():
    """Liste des techniques disponibles, issue de la table techniques (source de vérité).
    Retourne juste les noms (strings)."""
    db = get_db()
    result = rows(db.execute("SELECT nom FROM techniques ORDER BY nom"))
    return jsonify([r["nom"] for r in result])

@app.route("/api/utilisateurs",methods=["POST"])
@require_role("admin","manager")
def create_utilisateur():
    d=request.json or {}
    if not all([d.get("nom"),d.get("email"),d.get("password")]): return jsonify({"error":"nom,email,password requis"}),400
    if len(d["password"]) < 8: return jsonify({"error":"Mot de passe trop court (8 caracteres minimum)"}),400
    db=get_db()
    matricule = (d.get("matricule") or "").strip()
    manager_id = to_int(d.get("manager_id")) or None
    techniques_csv = _techniques_from_body(d.get("techniques"))
    poste_id = to_int(d.get("poste_id")) or None
    superieur_id = to_int(d.get("superieur_id")) or None
    try:
        db.execute("INSERT INTO utilisateurs (nom,email,password,role,matricule,manager_id,techniques,poste_id,superieur_id) VALUES (?,?,?,?,?,?,?,?,?)",
                   (d["nom"],d["email"].strip().lower(),hash_password(d["password"]),d.get("role","technicien"),matricule,manager_id,techniques_csv,poste_id,superieur_id))
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        log_action(request.user, "CREATE", "utilisateur", new_id, d["nom"], f"role={d.get('role','technicien')}")
        return jsonify({"id":new_id}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/utilisateurs/<int:uid>",methods=["PATCH"])
@require_role("admin","manager")
def update_utilisateur(uid):
    d = request.json or {}
    db = get_db()
    fields = {}
    for f in ["nom","email","role","actif","matricule"]:
        if f in d: fields[f] = d[f]
    # manager_id : None si vide, sinon int
    if "manager_id" in d:
        mid = d.get("manager_id")
        fields["manager_id"] = to_int(mid) if mid else None
    # techniques : liste ou CSV → CSV propre
    if "techniques" in d:
        fields["techniques"] = _techniques_from_body(d.get("techniques"))
    # poste_id et superieur_id : None si vide, sinon int
    if "poste_id" in d:
        pid = d.get("poste_id")
        fields["poste_id"] = to_int(pid) if pid else None
    if "superieur_id" in d:
        sid = d.get("superieur_id")
        fields["superieur_id"] = to_int(sid) if sid else None
    if fields.get("email"): fields["email"] = fields["email"].strip().lower()
    if d.get("password"):
        if len(d["password"]) < 8:
            return jsonify({"error":"Mot de passe trop court (8 caracteres minimum)"}),400
        fields["password"] = hash_password(d["password"])
        # Révoquer toutes les sessions existantes
        current = one(db.execute("SELECT token_version FROM utilisateurs WHERE id=?", (uid,)))
        fields["token_version"] = (current["token_version"] or 0) + 1 if current else 1
    n = safe_update(db, "utilisateurs", uid, fields)
    if n == 0: return jsonify({"error":"Rien"}), 400
    db.commit()
    # Log : on récupère le nom pour tracer
    u_info = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?", (uid,)))
    label = (u_info or {}).get("nom", f"uid={uid}")
    changes = ", ".join([f"{k}={v}" for k,v in fields.items() if k != "password"])
    if "password" in fields: changes += (", " if changes else "") + "password=***"
    log_action(request.user, "UPDATE", "utilisateur", uid, label, changes)
    return jsonify({"ok":True})

@app.route("/api/utilisateurs/<int:uid>",methods=["DELETE"])
@require_role("admin")
def delete_utilisateur(uid):
    if uid==request.user["id"]: return jsonify({"error":"Impossible de supprimer son propre compte"}),400
    db=get_db()
    # Récupérer le nom avant suppression pour le log
    u_info = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?", (uid,)))
    label = (u_info or {}).get("nom", f"uid={uid}")
    db.execute("DELETE FROM utilisateurs WHERE id=?",(uid,)); db.commit()
    log_action(request.user, "DELETE", "utilisateur", uid, label)
    return jsonify({"ok":True})

@app.route("/api/utilisateurs/me",methods=["PATCH"])
@require_auth
def update_me():
    d = request.json or {}
    db = get_db()
    uid = request.user["id"]
    fields = {}
    if "nom" in d: fields["nom"] = d["nom"]
    if d.get("password"):
        if len(d["password"]) < 8:
            return jsonify({"error":"Mot de passe trop court (8 caracteres minimum)"}),400
        fields["password"] = hash_password(d["password"])
        current = one(db.execute("SELECT token_version FROM utilisateurs WHERE id=?", (uid,)))
        fields["token_version"] = (current["token_version"] or 0) + 1 if current else 1
    n = safe_update(db, "utilisateurs", uid, fields)
    if n == 0: return jsonify({"error":"Rien"}), 400
    db.commit()
    # Si MDP changé, le client devra se reconnecter (token invalide immédiatement)
    return jsonify({"ok":True, "password_changed": "password" in fields})

# ══ CLIENTS ══
@app.route("/api/clients")
@require_auth
def get_clients():
    return jsonify(rows(get_db().execute("SELECT * FROM clients ORDER BY societe")))

@app.route("/api/clients",methods=["POST"])
@require_role("admin","manager")
def create_client():
    d=request.json or {}
    if not d.get("societe"): return jsonify({"error":"societe requis"}),400
    db=get_db()
    db.execute("INSERT INTO clients (societe,nom,prenom,email,telephone,notes) VALUES (?,?,?,?,?,?)",
               (d["societe"],d.get("nom",""),d.get("prenom",""),d.get("email",""),d.get("telephone",""),d.get("notes","")))
    db.commit(); return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/clients/<int:cid>",methods=["PATCH"])
@require_role("admin","manager")
def update_client(cid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["societe","nom","prenom","email","telephone","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(cid); db.execute(f"UPDATE clients SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/clients/<int:cid>",methods=["DELETE"])
@require_role("admin")
def delete_client(cid):
    db=get_db(); db.execute("DELETE FROM clients WHERE id=?",(cid,)); db.commit()
    return jsonify({"ok":True})

# ══ PROJETS ══
@app.route("/api/projets/all")
@require_auth
def get_projets_all():
    """Retourne TOUS les projets, quel que soit le rôle. Utilisé notamment
    par le mobile pour permettre aux techniciens de créer des bons dépannage
    sur n'importe quel projet."""
    db = get_db()
    return jsonify(rows(db.execute("""SELECT p.*,c.societe AS client_nom,m.nom AS manager_nom
        FROM projets p LEFT JOIN clients c ON p.client_id=c.id
        LEFT JOIN utilisateurs m ON p.manager_id=m.id ORDER BY p.nom""")))

@app.route("/api/projets")
@require_auth
def get_projets():
    db=get_db(); u=request.user
    if u["role"]=="technicien":
        return jsonify(rows(db.execute("""SELECT p.*,c.societe AS client_nom,m.nom AS manager_nom
            FROM projets p LEFT JOIN clients c ON p.client_id=c.id
            LEFT JOIN utilisateurs m ON p.manager_id=m.id
            WHERE p.id IN (
                SELECT DISTINCT e.projet_id FROM equipements e
                JOIN interventions i ON i.equipement_id=e.id WHERE i.technicien_id=?
                UNION
                SELECT DISTINCT e.projet_id FROM equipements e
                JOIN interventions i ON i.equipement_id=e.id
                JOIN equipe_membres em ON em.equipe_id=i.equipe_id WHERE em.technicien_id=?
            ) ORDER BY p.nom""",(u["id"],u["id"]))))
    if u["role"]=="manager":
        # Manager : ses propres projets + les projets contenant des équipements d'une technique qu'il gère
        udb = one(db.execute("SELECT techniques FROM utilisateurs WHERE id=?", (u["id"],)))
        tech_csv = (udb and udb.get("techniques")) or ""
        tech_list = [t.strip() for t in tech_csv.split(",") if t.strip()]
        if tech_list:
            placeholders = ",".join(["?"] * len(tech_list))
            sql = f"""SELECT p.*,c.societe AS client_nom,m.nom AS manager_nom
                FROM projets p LEFT JOIN clients c ON p.client_id=c.id
                LEFT JOIN utilisateurs m ON p.manager_id=m.id
                WHERE p.manager_id=?
                   OR p.id IN (SELECT DISTINCT e.projet_id FROM equipements e WHERE e.type_technique IN ({placeholders}))
                ORDER BY p.nom"""
            return jsonify(rows(db.execute(sql, [u["id"]] + tech_list)))
        else:
            return jsonify(rows(db.execute("""SELECT p.*,c.societe AS client_nom,m.nom AS manager_nom
                FROM projets p LEFT JOIN clients c ON p.client_id=c.id
                LEFT JOIN utilisateurs m ON p.manager_id=m.id
                WHERE p.manager_id=? ORDER BY p.nom""", (u["id"],))))
    return jsonify(rows(db.execute("""SELECT p.*,c.societe AS client_nom,m.nom AS manager_nom
        FROM projets p LEFT JOIN clients c ON p.client_id=c.id
        LEFT JOIN utilisateurs m ON p.manager_id=m.id ORDER BY p.nom""")))

@app.route("/api/projets",methods=["POST"])
@require_role("admin","manager")
def create_projet():
    d=request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db=get_db(); num=d.get("numero_projet") or next_numero(db,"P","projets","numero_projet")
    db.execute("""INSERT INTO projets (numero_projet,nom,client_id,manager_id,description,
               date_debut,date_fin,statut,ville,code_postal,deplacement_km,nb_deplacements)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
               (num,d["nom"],to_int(d.get("client_id")),to_int(d.get("manager_id")),
                d.get("description",""),d.get("date_debut") or None,d.get("date_fin") or None,
                d.get("statut","EN_COURS"),d.get("ville",""),d.get("code_postal",""),
                float(d.get("deplacement_km") or 0), int(d.get("nb_deplacements") or 0)))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    log_action(request.user, "CREATE", "projet", new_id, f"{num} - {d['nom']}")
    return jsonify({"id":new_id}),201


@app.route("/api/projets/<int:pid>")
@require_auth
def get_projet(pid):
    db = get_db()
    p = one(db.execute(
        "SELECT p.*,c.societe AS client_nom,m.nom AS manager_nom"
        " FROM projets p LEFT JOIN clients c ON p.client_id=c.id"
        " LEFT JOIN utilisateurs m ON p.manager_id=m.id WHERE p.id=?",(pid,)))
    if not p: return jsonify({"error":"Non trouve"}),404
    p["equipements"] = rows(db.execute(
        "SELECT e.* FROM equipements e WHERE e.projet_id=? ORDER BY e.designation",(pid,)))
    for e in p["equipements"]:
        e["criticite"] = criticite(e["id"],db)
    return jsonify(p)

@app.route("/api/projets/<int:pid>",methods=["PATCH"])
@require_role("admin","manager")
def update_projet(pid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    logger.info(f"[PATCH projet] pid={pid} body={d}")
    for f in ["nom","client_id","manager_id","description","date_debut","date_fin","statut","numero_projet","ville","code_postal","deplacement_km"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(pid); db.execute(f"UPDATE projets SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    logger.info(f"[PATCH projet] pid={pid} champs={sets}")
    p_info = one(db.execute("SELECT nom,numero_projet FROM projets WHERE id=?", (pid,)))
    label = f"{(p_info or {}).get('numero_projet','')} - {(p_info or {}).get('nom','')}" if p_info else f"pid={pid}"
    changes = ", ".join([f"{k}={v}" for k,v in d.items()])
    log_action(request.user, "UPDATE", "projet", pid, label, changes[:500])
    return jsonify({"ok":True})

@app.route("/api/projets/<int:pid>",methods=["DELETE"])
@require_role("admin")
def delete_projet(pid):
    db=get_db()
    p_info = one(db.execute("SELECT nom,numero_projet FROM projets WHERE id=?", (pid,)))
    label = f"{(p_info or {}).get('numero_projet','')} - {(p_info or {}).get('nom','')}" if p_info else f"pid={pid}"
    db.execute("DELETE FROM projets WHERE id=?",(pid,)); db.commit()
    log_action(request.user, "DELETE", "projet", pid, label)
    return jsonify({"ok":True})

# ══ EQUIPEMENTS ══
@app.route("/api/equipements")
@require_auth
def get_equipements():
    db=get_db(); u=request.user
    sql="""SELECT e.*,p.nom AS projet_nom,p.numero_projet,g.nom AS gamme_nom,t.nom AS technique_nom
           FROM equipements e JOIN projets p ON e.projet_id=p.id
           LEFT JOIN gammes g ON e.gamme_id=g.id
           LEFT JOIN techniques t ON e.technique_id=t.id WHERE 1=1"""
    params=[]
    if request.args.get("projet_id"): sql+=" AND e.projet_id=?"; params.append(request.args["projet_id"])
    # Filtrage par rôle : manager = projets qu'il gère + techniques qu'il gère
    if u["role"]=="manager":
        udb = one(db.execute("SELECT techniques FROM utilisateurs WHERE id=?", (u["id"],)))
        tech_csv = (udb and udb.get("techniques")) or ""
        tech_list = [t.strip() for t in tech_csv.split(",") if t.strip()]
        if tech_list:
            placeholders = ",".join(["?"] * len(tech_list))
            sql += f" AND (p.manager_id=? OR e.type_technique IN ({placeholders}))"
            params = params + [u["id"]] + tech_list
        else:
            sql += " AND p.manager_id=?"
            params.append(u["id"])
    equips=rows(db.execute(sql+" ORDER BY p.nom,e.designation",params))
    for e in equips:
        e["criticite"]=criticite(e["id"],db)
        e["nb_maintenance"]=db.execute("SELECT COUNT(*) FROM interventions WHERE equipement_id=? AND type='MAINTENANCE'",(e["id"],)).fetchone()[0]
        e["nb_depannage"]=db.execute("SELECT COUNT(*) FROM interventions WHERE equipement_id=? AND type='DEPANNAGE'",(e["id"],)).fetchone()[0]
        e["gammes"]=rows(db.execute("""SELECT g.*,
            eg.planning_id AS eg_planning_id,
            eg.semaine_planif AS eg_semaine_planif,
            eg.jour_semaine_planif AS eg_jour_semaine_planif,
            eg.intervention_samedi AS eg_intervention_samedi,
            eg.intervention_dimanche AS eg_intervention_dimanche,
            eg.planif_mode AS eg_planif_mode,
            eg.nth_semaine_mois AS eg_nth_semaine_mois
            FROM gammes g JOIN equipement_gammes eg ON g.id=eg.gamme_id
            WHERE eg.equipement_id=? ORDER BY g.nom""",(e["id"],)))
    return jsonify(equips)

@app.route("/api/equipements/<int:eid>")
@require_auth
def get_equipement(eid):
    db=get_db()
    e=one(db.execute("""SELECT e.*,p.nom AS projet_nom,p.numero_projet,g.nom AS gamme_nom,t.nom AS technique_nom
        FROM equipements e JOIN projets p ON e.projet_id=p.id
        LEFT JOIN gammes g ON e.gamme_id=g.id LEFT JOIN techniques t ON e.technique_id=t.id
        WHERE e.id=?""",(eid,)))
    if not e: return jsonify({"error":"Non trouve"}),404
    pieces_raw=rows(db.execute("SELECT * FROM pieces WHERE equipement_id=? ORDER BY type_piece",(eid,)))
    for p in pieces_raw:
        ns=statut_piece(p.get("date_fin_de_vie"))
        if ns!=p.get("statut") and p.get("date_fin_de_vie"):
            db.execute("UPDATE pieces SET statut=? WHERE id=?",(ns,p["id"])); p["statut"]=ns
    db.commit()
    e["pieces"]=pieces_raw; e["criticite"]=criticite(eid,db)
    # Gammes : récupérer aussi la planif par gamme (colonnes ajoutées sur equipement_gammes)
    e["gammes"]=rows(db.execute("""SELECT g.*,
        eg.planning_id AS eg_planning_id,
        eg.semaine_planif AS eg_semaine_planif,
        eg.jour_semaine_planif AS eg_jour_semaine_planif,
        eg.intervention_samedi AS eg_intervention_samedi,
        eg.intervention_dimanche AS eg_intervention_dimanche,
        eg.planif_mode AS eg_planif_mode,
        eg.nth_semaine_mois AS eg_nth_semaine_mois
        FROM gammes g JOIN equipement_gammes eg ON g.id=eg.gamme_id
        WHERE eg.equipement_id=? ORDER BY g.nom""",(eid,)))
    return jsonify(e)

@app.route("/api/equipements",methods=["POST"])
@require_role("admin","manager")
def create_equipement():
    d=request.json or {}
    if not all([d.get("designation"),d.get("projet_id"),d.get("type_technique")]): return jsonify({"error":"designation,projet_id,type_technique requis"}),400
    db=get_db()
    db.execute("INSERT INTO equipements (projet_id,designation,type_technique,localisation,marque,modele,puissance,numero_serie,in_out,date_mise_en_service,statut,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (d["projet_id"],d["designation"],d["type_technique"],d.get("localisation",""),d.get("marque",""),d.get("modele",""),d.get("puissance",""),d.get("numero_serie",""),d.get("in_out",""),d.get("date_mise_en_service") or None,d.get("statut","EN_SERVICE"),d.get("notes","")))
    new_eid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    # Format gammes : peut être [id, id, ...] (ancien) ou [{gamme_id, semaine_planif, ...}, ...] (nouveau)
    for g in d.get("gammes",[]):
        try:
            if isinstance(g, dict):
                gid = int(g.get("gamme_id") or g.get("id"))
                db.execute("""INSERT OR IGNORE INTO equipement_gammes
                    (equipement_id, gamme_id, planning_id, semaine_planif, jour_semaine_planif,
                     intervention_samedi, intervention_dimanche, planif_mode, nth_semaine_mois)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (new_eid, gid,
                     to_int(g.get("planning_id")),
                     to_int(g.get("semaine_planif")),
                     to_int(g.get("jour_semaine_planif")),
                     1 if g.get("intervention_samedi") else 0,
                     1 if g.get("intervention_dimanche") else 0,
                     g.get("planif_mode") or 'SEMAINE',
                     to_int(g.get("nth_semaine_mois"))))
            else:
                db.execute("INSERT OR IGNORE INTO equipement_gammes (equipement_id, gamme_id) VALUES (?,?)",
                           (new_eid, int(g)))
        except Exception: pass
    db.commit()
    # Générer le premier bon si au moins une gamme a une planif configurée
    has_planif = False
    try:
        has_planif = bool(one(db.execute("""SELECT 1 FROM equipement_gammes
            WHERE equipement_id=? AND planning_id IS NOT NULL
            AND semaine_planif IS NOT NULL AND jour_semaine_planif IS NOT NULL
            LIMIT 1""", (new_eid,))))
    except Exception: pass
    if has_planif:
        try:
            from datetime import date as _date
            generate_next_bon(new_eid, db, _date.today().isoformat())
        except Exception as e_gen:
            pass
    return jsonify({"id":new_eid}),201

@app.route("/api/equipements/<int:eid>",methods=["PATCH"])
@require_role("admin","manager")
def update_equipement(eid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["designation","type_technique","projet_id","localisation","marque","modele","puissance","numero_serie","in_out","date_mise_en_service","statut","technique_id","notes","planning_id","semaine_planif","jour_semaine_planif","intervention_samedi","intervention_dimanche"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if sets: params.append(eid); db.execute(f"UPDATE equipements SET {chr(44).join(sets)} WHERE id=?",params)
    if "gammes" in d:
        db.execute("DELETE FROM equipement_gammes WHERE equipement_id=?",(eid,))
        for g in d["gammes"]:
            try:
                if isinstance(g, dict):
                    gid = int(g.get("gamme_id") or g.get("id"))
                    db.execute("""INSERT OR IGNORE INTO equipement_gammes
                        (equipement_id, gamme_id, planning_id, semaine_planif, jour_semaine_planif,
                         intervention_samedi, intervention_dimanche, planif_mode, nth_semaine_mois)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        (eid, gid,
                         to_int(g.get("planning_id")),
                         to_int(g.get("semaine_planif")),
                         to_int(g.get("jour_semaine_planif")),
                         1 if g.get("intervention_samedi") else 0,
                         1 if g.get("intervention_dimanche") else 0,
                         g.get("planif_mode") or 'SEMAINE',
                         to_int(g.get("nth_semaine_mois"))))
                else:
                    db.execute("INSERT OR IGNORE INTO equipement_gammes (equipement_id, gamme_id) VALUES (?,?)",
                               (eid, int(g)))
            except Exception: pass
    db.commit(); return jsonify({"ok":True})

@app.route("/api/equipements/<int:eid>",methods=["DELETE"])
@require_role("admin","manager")
def delete_equipement(eid):
    db=get_db(); db.execute("DELETE FROM pieces WHERE equipement_id=?",(eid,))
    for i in rows(db.execute("SELECT id FROM interventions WHERE equipement_id=?",(eid,))):
        db.execute("DELETE FROM comptes_rendus WHERE intervention_id=?",(i["id"],))
    db.execute("DELETE FROM interventions WHERE equipement_id=?",(eid,))
    db.execute("DELETE FROM equipements WHERE id=?",(eid,)); db.commit()
    return jsonify({"ok":True})

# ══ PIECES ══
@app.route("/api/pieces")
@require_auth
def get_pieces():
    db=get_db()
    sql="""SELECT p.*,e.designation AS equip_nom,pr.nom AS projet_nom
           FROM pieces p JOIN equipements e ON p.equipement_id=e.id
           JOIN projets pr ON e.projet_id=pr.id WHERE 1=1"""
    params=[]
    if request.args.get("equipement_id"): sql+=" AND p.equipement_id=?"; params.append(request.args["equipement_id"])
    if request.args.get("alertes"): sql+=" AND p.statut IN ('A_SURVEILLER','A_REMPLACER')"
    pieces=rows(db.execute(sql+" ORDER BY p.date_fin_de_vie",params))
    for p in pieces:
        ns=statut_piece(p.get("date_fin_de_vie"))
        if ns!=p.get("statut") and p.get("date_fin_de_vie"):
            db.execute("UPDATE pieces SET statut=? WHERE id=?",(ns,p["id"])); p["statut"]=ns
    db.commit(); return jsonify(pieces)

@app.route("/api/pieces",methods=["POST"])
@require_auth
def create_piece():
    d=request.json or {}
    if not all([d.get("equipement_id"),d.get("type_piece")]): return jsonify({"error":"equipement_id et type_piece requis"}),400
    db=get_db(); dv=d.get("date_fin_de_vie") or None
    if not dv and d.get("date_installation") and d.get("duree_vie_estimee"):
        try:
            di=datetime.strptime(d["date_installation"],"%Y-%m-%d")
            dv=(di+timedelta(days=int(d["duree_vie_estimee"])*365)).strftime("%Y-%m-%d")
        except Exception: pass
    st=statut_piece(dv)
    db.execute("INSERT INTO pieces (equipement_id,type_piece,date_installation,duree_vie_estimee,date_fin_de_vie,statut,quantite,numero_serie,reference,commentaire) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (d["equipement_id"],d["type_piece"],d.get("date_installation") or None,d.get("duree_vie_estimee") or None,dv,st,d.get("quantite",1),d.get("numero_serie",""),d.get("reference",""),d.get("commentaire","")))
    db.commit(); return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/pieces/<int:pid>",methods=["PATCH"])
@require_auth
def update_piece(pid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["type_piece","date_installation","duree_vie_estimee","date_fin_de_vie","statut","quantite","numero_serie","reference","commentaire"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(pid)
    db.execute(f"UPDATE pieces SET {chr(44).join(sets)} WHERE id=?",params)
    # Recalculer date_fin_de_vie et statut si date_installation ou duree_vie changent
    if "date_installation" in d or "duree_vie_estimee" in d or "date_fin_de_vie" in d:
        piece = one(db.execute("SELECT date_installation,duree_vie_estimee,date_fin_de_vie FROM pieces WHERE id=?",(pid,)))
        if piece:
            fdv = piece["date_fin_de_vie"]
            # Si date_installation + duree_vie fournis, recalculer fdv
            if piece["date_installation"] and piece["duree_vie_estimee"] and not d.get("date_fin_de_vie"):
                try:
                    from datetime import datetime, timedelta
                    di = datetime.strptime(piece["date_installation"],"%Y-%m-%d")
                    fdv = (di + timedelta(days=int(piece["duree_vie_estimee"])*365)).strftime("%Y-%m-%d")
                    db.execute("UPDATE pieces SET date_fin_de_vie=? WHERE id=?",(fdv,pid))
                except Exception: pass
            # Recalculer statut depuis fdv
            new_statut = statut_piece(fdv)
            # Ne recalculer que si statut pas explicitement fourni
            if "statut" not in d:
                db.execute("UPDATE pieces SET statut=? WHERE id=?",(new_statut,pid))
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/pieces/<int:pid>",methods=["DELETE"])
@require_auth
def delete_piece(pid):
    db=get_db(); db.execute("DELETE FROM pieces WHERE id=?",(pid,)); db.commit()
    return jsonify({"ok":True})

# ══ EQUIPES ══
@app.route("/api/equipes")
@require_auth
def get_equipes():
    db=get_db()
    equipes=rows(db.execute("SELECT e.*,u.nom AS manager_nom FROM equipes e LEFT JOIN utilisateurs u ON e.manager_id=u.id ORDER BY e.nom"))
    for eq in equipes:
        eq["membres"]=rows(db.execute("""SELECT u.id,u.nom,u.email FROM utilisateurs u
            JOIN equipe_membres em ON em.technicien_id=u.id WHERE em.equipe_id=?""",(eq["id"],)))
    return jsonify(equipes)

@app.route("/api/equipes",methods=["POST"])
@require_role("admin","manager")
def create_equipe():
    d=request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db=get_db(); db.execute("INSERT INTO equipes (nom,manager_id) VALUES (?,?)",(d["nom"],to_int(d.get("manager_id"))))
    db.commit(); eid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for mid in d.get("membres",[]):
        try: db.execute("INSERT OR IGNORE INTO equipe_membres VALUES (?,?)",(eid,int(mid)))
        except Exception: pass
    db.commit(); return jsonify({"id":eid}),201

@app.route("/api/equipes/<int:eid>",methods=["PATCH"])
@require_role("admin","manager")
def update_equipe(eid):
    d=request.json or {}; db=get_db()
    if "nom" in d or "manager_id" in d:
        sets,params=[],[]
        if "nom" in d: sets.append("nom=?"); params.append(d["nom"])
        if "manager_id" in d: sets.append("manager_id=?"); params.append(to_int(d["manager_id"]))
        params.append(eid); db.execute(f"UPDATE equipes SET {chr(44).join(sets)} WHERE id=?",params)
    if "membres" in d:
        db.execute("DELETE FROM equipe_membres WHERE equipe_id=?",(eid,))
        for mid in d["membres"]:
            try: db.execute("INSERT OR IGNORE INTO equipe_membres VALUES (?,?)",(eid,int(mid)))
            except Exception: pass
    db.commit(); return jsonify({"ok":True})

@app.route("/api/equipes/<int:eid>",methods=["DELETE"])
@require_role("admin","manager")
def delete_equipe(eid):
    db=get_db(); db.execute("DELETE FROM equipe_membres WHERE equipe_id=?",(eid,))
    db.execute("DELETE FROM equipes WHERE id=?",(eid,)); db.commit()
    return jsonify({"ok":True})

# ══ INTERVENTIONS ══
@app.route("/api/interventions")
@require_auth
def get_interventions():
    db=get_db(); u=request.user
    sql="""SELECT i.*,e.designation AS equip_nom,e.type_technique,
                  p.nom AS projet_nom,p.numero_projet,c.societe AS client_nom,
                  u.nom AS technicien_nom,eq.nom AS equipe_nom,
                  (SELECT GROUP_CONCAT(it.utilisateur_id)
                   FROM intervention_techniciens it WHERE it.intervention_id=i.id) AS _tech_ids_csv
           FROM interventions i JOIN equipements e ON i.equipement_id=e.id
           JOIN projets p ON e.projet_id=p.id LEFT JOIN clients c ON p.client_id=c.id
           LEFT JOIN utilisateurs u ON i.technicien_id=u.id
           LEFT JOIN equipes eq ON i.equipe_id=eq.id WHERE 1=1"""
    params=[]
    if u["role"]=="technicien":
        sql+=(" AND (i.technicien_id=? "
              "OR i.equipe_id IN (SELECT equipe_id FROM equipe_membres WHERE technicien_id=?) "
              "OR EXISTS (SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND it.utilisateur_id=?) "
              "OR EXISTS (SELECT 1 FROM cr_intervenants ci JOIN comptes_rendus cr ON ci.cr_id=cr.id "
              "           WHERE cr.intervention_id=i.id AND ci.utilisateur_id=?))")
        params+=[u["id"],u["id"],u["id"],u["id"]]
    elif u["role"]=="manager":
        # Manager : bons dont le projet lui appartient, OU dont un tech de son équipe est assigné, OU lui-même,
        # OU bons liés à une technique qu'il gère (manager technique)
        # Récupérer ses techniques
        udb = one(get_db().execute("SELECT techniques FROM utilisateurs WHERE id=?", (u["id"],)))
        tech_csv = (udb and udb.get("techniques")) or ""
        tech_list = [t.strip() for t in tech_csv.split(",") if t.strip()]
        conditions = [
            "p.manager_id=?",
            "i.technicien_id=?",
            "i.technicien_id IN (SELECT id FROM utilisateurs WHERE manager_id=?)",
            "EXISTS (SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND "
            "  (it.utilisateur_id=? OR it.utilisateur_id IN (SELECT id FROM utilisateurs WHERE manager_id=?)))",
            "EXISTS (SELECT 1 FROM cr_intervenants ci JOIN comptes_rendus cr ON ci.cr_id=cr.id "
            "  WHERE cr.intervention_id=i.id AND (ci.utilisateur_id=? OR ci.utilisateur_id IN (SELECT id FROM utilisateurs WHERE manager_id=?)))"
        ]
        params_mgr = [u["id"], u["id"], u["id"], u["id"], u["id"], u["id"], u["id"]]
        if tech_list:
            placeholders = ",".join(["?"] * len(tech_list))
            conditions.append(f"e.type_technique IN ({placeholders})")
            params_mgr += tech_list
        sql += " AND (" + " OR ".join(conditions) + ")"
        params += params_mgr
        logger.info(f"[interventions manager u={u['id']}] techniques={tech_list} subordinates={rows(get_db().execute('SELECT id,nom FROM utilisateurs WHERE manager_id=?',(u['id'],)))}")
    # admin : pas de filtre, voit tout
    for arg,col in [("type","i.type"),("statut","i.statut"),("equipement_id","i.equipement_id"),("projet_id","e.projet_id")]:
        if request.args.get(arg): sql+=f" AND {col}=?"; params.append(request.args[arg])
    result = rows(db.execute(sql+" ORDER BY CASE WHEN i.date_prevue IS NULL THEN 1 ELSE 0 END, i.date_prevue ASC, i.created_at DESC",params))
    # Convertir la CSV en liste d'int pour chaque intervention
    for r in result:
        csv_ids = r.pop("_tech_ids_csv", None)
        if csv_ids:
            r["technicien_ids"] = [int(x) for x in csv_ids.split(",") if x]
        else:
            r["technicien_ids"] = [r["technicien_id"]] if r.get("technicien_id") else []
        # Pour les bons de dépannage ET maintenance avec CR : ajouter la liste des CRs
        # (utilisé pour le planning : dépannage = toujours CRs ; maintenance = CRs s'il y en a)
        if r.get("type") in ("DEPANNAGE", "MAINTENANCE"):
            try:
                crs_light = rows(db.execute(
                    "SELECT id, numero, date_intervention FROM comptes_rendus WHERE intervention_id=? ORDER BY date_intervention, id",
                    (r["id"],)))
                # Pour chaque CR, récupérer l'intervalle horaire global (min heure_debut → max heure_fin)
                # + la liste des intervenants (pour affichage planning multi-tech)
                for cr in crs_light:
                    try:
                        horaires = one(db.execute(
                            """SELECT MIN(NULLIF(heure_debut,'')) AS h_min, MAX(NULLIF(heure_fin,'')) AS h_max
                               FROM cr_intervenants WHERE cr_id=?""", (cr["id"],)))
                        cr["heure_debut"] = (horaires or {}).get("h_min") or ""
                        cr["heure_fin"] = (horaires or {}).get("h_max") or ""
                    except Exception:
                        cr["heure_debut"] = ""
                        cr["heure_fin"] = ""
                    # Liste des techniciens présents sur ce CR (ids uniquement, pour filtrage planning)
                    try:
                        tech_rows = rows(db.execute(
                            "SELECT DISTINCT utilisateur_id FROM cr_intervenants WHERE cr_id=? AND utilisateur_id IS NOT NULL",
                            (cr["id"],)))
                        cr["technicien_ids"] = [t["utilisateur_id"] for t in tech_rows if t.get("utilisateur_id")]
                    except Exception:
                        cr["technicien_ids"] = []
                    # Détail des intervenants : date + horaires individuels (pour éclater les tuiles par date si différentes)
                    try:
                        cr["intervenants_detail"] = rows(db.execute(
                            """SELECT utilisateur_id, nom,
                                      NULLIF(date,'') AS date,
                                      NULLIF(heure_debut,'') AS heure_debut,
                                      NULLIF(heure_fin,'') AS heure_fin
                               FROM cr_intervenants WHERE cr_id=?""",
                            (cr["id"],)))
                    except Exception:
                        cr["intervenants_detail"] = []
                r["comptes_rendus_light"] = crs_light
            except Exception:
                r["comptes_rendus_light"] = []
    return jsonify(result)

@app.route("/api/interventions/<int:iid>")
@require_auth
def get_intervention(iid):
    db=get_db()
    i=one(db.execute("""SELECT i.*,e.designation AS equip_nom,e.type_technique,
           p.nom AS projet_nom,c.societe AS client_nom,u.nom AS technicien_nom
           FROM interventions i JOIN equipements e ON i.equipement_id=e.id
           JOIN projets p ON e.projet_id=p.id LEFT JOIN clients c ON p.client_id=c.id
           LEFT JOIN utilisateurs u ON i.technicien_id=u.id WHERE i.id=?""",(iid,)))
    if not i: return jsonify({"error":"Non trouve"}),404
    crs=rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
    for cr in crs:
        cr["intervenants"]=rows(db.execute("""SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
            FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id
            WHERE ci.cr_id=?""",(cr["id"],)))
        try:
            cr["materiels"]=rows(db.execute("SELECT * FROM cr_materiels WHERE cr_id=? ORDER BY ordre,id",(cr["id"],)))
        except: cr["materiels"]=[]
    i["comptes_rendus"]=crs
    # Créneaux (pour interventions multi-jours)
    i["creneaux"]=rows(db.execute("""SELECT c.*, u.nom AS technicien_nom
        FROM intervention_creneaux c LEFT JOIN utilisateurs u ON c.technicien_id=u.id
        WHERE c.intervention_id=? ORDER BY c.date, c.heure_debut""",(iid,)))
    # Techniciens affectés (multi)
    techs = rows(db.execute("""SELECT it.utilisateur_id AS id, u.nom
        FROM intervention_techniciens it JOIN utilisateurs u ON it.utilisateur_id=u.id
        WHERE it.intervention_id=? ORDER BY it.id""",(iid,)))
    # Fallback : si la table liaison est vide mais qu'il y a un technicien_id historique, on l'expose
    if not techs and i.get("technicien_id"):
        u = one(db.execute("SELECT id,nom FROM utilisateurs WHERE id=?",(i["technicien_id"],)))
        if u: techs = [u]
    i["techniciens"] = techs
    i["technicien_ids"] = [t["id"] for t in techs]
    return jsonify(i)

@app.route("/api/interventions",methods=["POST"])
@require_auth
def create_intervention():
    d=request.json or {}
    if not d.get("equipement_id"): return jsonify({"error":"equipement_id requis"}),400
    db=get_db()
    type_iv = d.get("type","MAINTENANCE")
    if type_iv not in ("MAINTENANCE","DEPANNAGE"):
        return jsonify({"error":"Type invalide"}),400
    try:
        # Préfixe numéro selon type : BP (maintenance), BC (dépannage)
        prefix_map = {"MAINTENANCE": "BP", "DEPANNAGE": "BC"}
        prefix = prefix_map.get(type_iv, "BT")
        num = next_numero(db, prefix, "interventions", "numero")
        # Normaliser la liste des techniciens
        # Accepte soit technicien_ids:[1,2,3] soit technicien_id:1 (legacy)
        tech_ids = d.get("technicien_ids") or []
        if not tech_ids and d.get("technicien_id"):
            tech_ids = [d.get("technicien_id")]
        tech_ids = [to_int(t) for t in tech_ids if t]
        # Dédoublonner en préservant l'ordre
        seen = set(); tech_ids_clean = []
        for t in tech_ids:
            if t and t not in seen: seen.add(t); tech_ids_clean.append(t)
        tech_ids = tech_ids_clean
        # Le "technicien principal" (colonne legacy) = premier de la liste
        main_tech = tech_ids[0] if tech_ids else None
        # Statut par défaut selon le type : MAINTENANCE = A_PLANIFIER, DEPANNAGE = PLANIFIEE
        default_statut = "A_PLANIFIER" if type_iv == "MAINTENANCE" else "PLANIFIEE"
        db.execute("""INSERT INTO interventions
            (numero,equipement_id,technicien_id,equipe_id,type,statut,date_prevue,description)
            VALUES (?,?,?,?,?,?,?,?)""",
            (num,d["equipement_id"],main_tech,to_int(d.get("equipe_id")),
             type_iv,d.get("statut",default_statut),d.get("date_prevue") or None,d.get("description","")))
        db.commit(); iid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
        # Enregistrer les techniciens affectés (y compris le principal pour cohérence)
        for tid in tech_ids:
            try:
                db.execute("INSERT OR IGNORE INTO intervention_techniciens (intervention_id,utilisateur_id) VALUES (?,?)",(iid,tid))
            except Exception as e:
                logger.warning(f"[ivtech] insert fail iv={iid} tech={tid}: {e}")
        if tech_ids: db.commit()
        # Créneaux optionnels à la création (intervention multi-jours)
        creneaux = d.get("creneaux") or []
        for c in creneaux:
            if not c.get("date"): continue
            db.execute("""INSERT INTO intervention_creneaux
                (intervention_id,date,heure_debut,heure_fin,technicien_id,notes)
                VALUES (?,?,?,?,?,?)""",
                (iid, c["date"], c.get("heure_debut",""), c.get("heure_fin",""),
                 to_int(c.get("technicien_id")), c.get("notes","")))
        if creneaux: db.commit()
        # Actions post-insert non-critiques (log + notif) : ne doivent PAS empêcher la création
        try:
            log_action(request.user, "CREATE", "intervention", iid, num, f"type={type_iv}")
        except Exception as e:
            logger.warning(f"[create_intervention] log_action échec iid={iid}: {e}")
        try:
            notify(iid,"Nouvelle intervention creee")
        except Exception as e:
            logger.warning(f"[create_intervention] notify échec iid={iid}: {e}")
        return jsonify({"id":iid,"numero":num}),201
    except Exception as e:
        import traceback
        logger.error(f"[create_intervention] ERREUR: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Erreur serveur : {str(e)}"}),500

@app.route("/api/interventions/<int:iid>",methods=["PATCH"])
@require_auth
def update_intervention(iid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    # Valider le type si fourni
    if "type" in d and d["type"] not in ("MAINTENANCE","DEPANNAGE"):
        return jsonify({"error":"Type invalide"}),400
    # Nettoyer les champs OFFRE obsolètes si envoyés par erreur
    d.pop("numero_offre", None)
    d.pop("numero_projet_offre", None)
    # Si technicien_ids fourni, extraire et synchroniser ensuite
    tech_ids = None
    if "technicien_ids" in d:
        raw = d.pop("technicien_ids") or []
        tech_ids = [to_int(t) for t in raw if t]
        # Dédoublonnage préservant l'ordre
        seen = set(); clean = []
        for t in tech_ids:
            if t and t not in seen: seen.add(t); clean.append(t)
        tech_ids = clean
        # Le premier est le "technicien principal" (compat colonne legacy)
        d["technicien_id"] = tech_ids[0] if tech_ids else None
    for f in ["technicien_id","equipe_id","type","statut","date_prevue","heure_prevue","date_realisation","description","rapport"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if "statut" in d and d["statut"]=="TERMINEE": sets.append("date_realisation=?"); params.append(now())
    if not sets and tech_ids is None: return jsonify({"error":"Rien"}),400
    if sets:
        params.append(iid); db.execute(f"UPDATE interventions SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    # Synchroniser la table de liaison si tech_ids a été fourni
    if tech_ids is not None:
        db.execute("DELETE FROM intervention_techniciens WHERE intervention_id=?",(iid,))
        for tid in tech_ids:
            try:
                db.execute("INSERT OR IGNORE INTO intervention_techniciens (intervention_id,utilisateur_id) VALUES (?,?)",(iid,tid))
            except Exception as e:
                logger.warning(f"[ivtech] update fail iv={iid} tech={tid}: {e}")
        db.commit()
    notify(iid,f"Intervention mise a jour : {d.get('statut','')}")
    # Log
    iv_info = one(db.execute("SELECT numero FROM interventions WHERE id=?", (iid,)))
    label = (iv_info or {}).get("numero", f"iv={iid}")
    changes = ", ".join([f"{k}={v}" for k,v in d.items() if k not in ("password",)])
    log_action(request.user, "UPDATE", "intervention", iid, label, changes[:500])
    # Générer le bon suivant si intervention terminée et planning configuré
    if d.get("statut") == "TERMINEE":
        iv = one(db.execute("SELECT * FROM interventions WHERE id=?", (iid,)))
        if iv and iv.get("equipement_id"):
            eq = one(db.execute("SELECT * FROM equipements WHERE id=?", (iv["equipement_id"],)))
            if eq and eq.get("planning_id") and eq.get("semaine_planif") is not None and eq.get("jour_semaine_planif") is not None:
                try:
                    generate_next_bon(eq["id"], db, iv.get("date_prevue") or iv.get("date_realisation"))
                except Exception as e_gen:
                    pass
    return jsonify({"ok":True})

@app.route("/api/interventions/<int:iid>",methods=["DELETE"])
@require_role("admin","manager")
def delete_intervention(iid):
    db=get_db()
    iv_info = one(db.execute("SELECT numero FROM interventions WHERE id=?", (iid,)))
    label = (iv_info or {}).get("numero", f"iv={iid}")
    db.execute("DELETE FROM comptes_rendus WHERE intervention_id=?",(iid,))
    db.execute("DELETE FROM intervention_creneaux WHERE intervention_id=?",(iid,))
    db.execute("DELETE FROM intervention_techniciens WHERE intervention_id=?",(iid,))
    db.execute("DELETE FROM interventions WHERE id=?",(iid,)); db.commit()
    log_action(request.user, "DELETE", "intervention", iid, label)
    return jsonify({"ok":True})

# ══ CRÉNEAUX D'INTERVENTION (planning multi-jours) ══
@app.route("/api/interventions/<int:iid>/creneaux")
@require_auth
def get_creneaux(iid):
    db=get_db()
    return jsonify(rows(db.execute("""SELECT c.*, u.nom AS technicien_nom
        FROM intervention_creneaux c LEFT JOIN utilisateurs u ON c.technicien_id=u.id
        WHERE c.intervention_id=? ORDER BY c.date, c.heure_debut""",(iid,))))

@app.route("/api/interventions/<int:iid>/creneaux",methods=["POST"])
@require_auth
def create_creneau(iid):
    d=request.json or {}
    if not d.get("date"): return jsonify({"error":"date requise"}),400
    db=get_db()
    if not one(db.execute("SELECT id FROM interventions WHERE id=?",(iid,))):
        return jsonify({"error":"intervention introuvable"}),404
    db.execute("""INSERT INTO intervention_creneaux
        (intervention_id,date,heure_debut,heure_fin,technicien_id,notes)
        VALUES (?,?,?,?,?,?)""",
        (iid,d["date"],d.get("heure_debut",""),d.get("heure_fin",""),
         to_int(d.get("technicien_id")),d.get("notes","")))
    db.commit()
    cid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id":cid}),201

@app.route("/api/creneaux/<int:cid>",methods=["PATCH"])
@require_auth
def update_creneau(cid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["date","heure_debut","heure_fin","technicien_id","notes"]:
        if f in d:
            sets.append(f"{f}=?"); params.append(d[f] if f!="technicien_id" else to_int(d[f]))
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(cid)
    db.execute(f"UPDATE intervention_creneaux SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/creneaux/<int:cid>",methods=["DELETE"])
@require_auth
def delete_creneau(cid):
    db=get_db(); db.execute("DELETE FROM intervention_creneaux WHERE id=?",(cid,)); db.commit()
    return jsonify({"ok":True})

# ══ OCCUPATIONS (congés, formation, etc.) ══

@app.route("/api/occupation_types")
@require_auth
def get_occupation_types():
    db = get_db()
    return jsonify(rows(db.execute("SELECT * FROM occupation_types WHERE actif=1 ORDER BY nom")))

@app.route("/api/occupation_types", methods=["POST"])
@require_role("admin")
def create_occupation_type():
    d = request.json or {}
    nom = (d.get("nom") or "").strip()
    if not nom: return jsonify({"error":"Nom requis"}), 400
    couleur = (d.get("couleur") or "#64748b").strip()
    aut_acc = 1 if d.get("autorise_accompagnants") else 0
    db = get_db()
    try:
        db.execute("INSERT INTO occupation_types (nom, couleur, autorise_accompagnants) VALUES (?,?,?)",
                   (nom, couleur, aut_acc))
        db.commit()
        return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error":"Ce type existe déjà"}), 400

@app.route("/api/occupation_types/<int:tid>", methods=["PATCH"])
@require_role("admin")
def update_occupation_type(tid):
    d = request.json or {}; db = get_db(); sets, params = [], []
    for f in ["nom", "couleur", "actif", "autorise_accompagnants"]:
        if f in d:
            sets.append(f"{f}=?")
            val = d[f]
            if f == "autorise_accompagnants":
                val = 1 if val else 0
            params.append(val)
    if not sets: return jsonify({"error":"Rien"}), 400
    params.append(tid)
    db.execute(f"UPDATE occupation_types SET {chr(44).join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/occupation_types/<int:tid>", methods=["DELETE"])
@require_role("admin")
def delete_occupation_type(tid):
    db = get_db()
    # Soft-delete : on garde les occupations existantes, on désactive juste le type
    used = one(db.execute("SELECT COUNT(*) AS n FROM occupations WHERE type_id=?", (tid,)))
    if used and used["n"] > 0:
        db.execute("UPDATE occupation_types SET actif=0 WHERE id=?", (tid,))
    else:
        db.execute("DELETE FROM occupation_types WHERE id=?", (tid,))
    db.commit()
    return jsonify({"ok": True})

def _calc_heures(hd, hf):
    """Calcule les heures entre deux horaires HH:MM.
    Si heure_fin < heure_debut, considère que c'est le lendemain (passage minuit).
    Ex: 18:00 → 02:30 = 8h30"""
    if not hd or not hf: return 0
    try:
        p1 = hd.split(":"); p2 = hf.split(":")
        m1 = int(p1[0]) * 60 + int(p1[1])
        m2 = int(p2[0]) * 60 + int(p2[1])
        diff_min = m2 - m1
        # Passage minuit : ajouter 24h si fin < début
        if diff_min < 0:
            diff_min += 24 * 60
        return round((diff_min / 60) * 100) / 100
    except Exception:
        return 0

@app.route("/api/occupations")
@require_auth
def get_occupations():
    """Liste des occupations. Technicien = les siennes. Admin/Manager = toutes.
    Paramètres : ?debut=YYYY-MM-DD&fin=YYYY-MM-DD&technicien_id=X"""
    u = request.user
    db = get_db()
    sql = """SELECT o.*, u.nom AS technicien_nom, ot.nom AS type_nom, ot.couleur AS type_couleur,
                    ot.autorise_accompagnants AS type_autorise_accompagnants
             FROM occupations o
             LEFT JOIN utilisateurs u ON o.technicien_id = u.id
             LEFT JOIN occupation_types ot ON o.type_id = ot.id
             WHERE 1=1"""
    params = []
    if u["role"] == "technicien":
        sql += " AND o.technicien_id = ?"
        params.append(u["id"])
    elif request.args.get("technicien_id"):
        sql += " AND o.technicien_id = ?"
        params.append(to_int(request.args["technicien_id"]))
    if request.args.get("debut"):
        sql += " AND o.date >= ?"
        params.append(request.args["debut"])
    if request.args.get("fin"):
        sql += " AND o.date <= ?"
        params.append(request.args["fin"])
    sql += " ORDER BY o.date DESC, o.heure_debut"
    result = rows(db.execute(sql, params))
    # Résoudre les accompagnants en noms + ids pour chaque occupation
    _resolve_accompagnants(db, result)
    return jsonify(result)

def _resolve_accompagnants(db, occupations_list):
    """Ajoute accompagnants_ids (liste d'ints) et accompagnants_noms (liste de str)
    à chaque occupation. Mutation en place."""
    if not occupations_list:
        return
    # Collecter tous les ids uniques
    all_ids = set()
    parsed_per_occ = []
    for o in occupations_list:
        raw = o.get("accompagnants_ids") or ""
        ids = []
        if raw and isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    ids = [int(x) for x in parsed if x is not None]
            except Exception:
                pass
        parsed_per_occ.append(ids)
        for x in ids: all_ids.add(x)
    # Résoudre d'un coup les noms
    noms_map = {}
    if all_ids:
        placeholders = ",".join(["?"] * len(all_ids))
        for r in db.execute(f"SELECT id, nom FROM utilisateurs WHERE id IN ({placeholders})", list(all_ids)):
            noms_map[r["id"]] = r["nom"]
    # Injecter dans chaque occupation
    for i, o in enumerate(occupations_list):
        ids = parsed_per_occ[i]
        o["accompagnants_ids"] = ids
        o["accompagnants_noms"] = [noms_map.get(x, "") for x in ids if x in noms_map]

@app.route("/api/occupations", methods=["POST"])
@require_auth
def create_occupation():
    d = request.json or {}
    u = request.user
    db = get_db()
    date = (d.get("date") or "").strip()
    if not date: return jsonify({"error":"Date requise"}), 400
    # Normaliser la liste des techniciens :
    # - si technicien_ids fourni → liste (multi-création / duplication)
    # - sinon technicien_id legacy (1 seule occupation)
    # - tech simple : force son propre id
    if u["role"] == "technicien":
        tech_ids = [u["id"]]
    else:
        raw_ids = d.get("technicien_ids")
        if isinstance(raw_ids, list) and raw_ids:
            tech_ids = [to_int(t) for t in raw_ids if t]
        else:
            single = to_int(d.get("technicien_id")) or u["id"]
            tech_ids = [single] if single else []
        # Dédoublonner en préservant l'ordre
        seen = set(); clean = []
        for t in tech_ids:
            if t and t not in seen: seen.add(t); clean.append(t)
        tech_ids = clean
    if not tech_ids:
        return jsonify({"error":"Au moins un technicien requis"}), 400
    heure_debut = (d.get("heure_debut") or "").strip()
    heure_fin = (d.get("heure_fin") or "").strip()
    total_heures = d.get("total_heures")
    if total_heures is None:
        total_heures = _calc_heures(heure_debut, heure_fin)
    try:
        total_heures = float(total_heures or 0)
    except Exception:
        total_heures = 0
    # Validation numero_projet si type=Offre (format P + 5 chiffres)
    type_id = to_int(d.get("type_id"))
    numero_projet = (d.get("numero_projet") or "").strip()
    nom_chantier = (d.get("nom_chantier") or "").strip()
    if type_id:
        t = one(db.execute("SELECT nom FROM occupation_types WHERE id=?", (type_id,)))
        if t and (t.get("nom") or "").strip().lower() == "offre":
            if not numero_projet:
                return jsonify({"error":"Numéro de projet requis pour une occupation de type Offre"}), 400
            if not re.match(r"^P\d{5}$", numero_projet):
                return jsonify({"error":"Le numéro de projet doit être au format P suivi de 5 chiffres (ex: P00042)"}), 400
            if not nom_chantier:
                return jsonify({"error":"Nom du chantier requis pour une occupation de type Offre"}), 400
        else:
            numero_projet = ""
            nom_chantier = ""
    else:
        numero_projet = ""
        nom_chantier = ""
    # Accompagnants (purement informatif)
    acc_raw = d.get("accompagnants_ids") or []
    acc_clean = []
    if isinstance(acc_raw, list):
        for x in acc_raw:
            xi = to_int(x)
            if xi: acc_clean.append(xi)
    elif isinstance(acc_raw, str) and acc_raw.strip():
        try:
            parsed = json.loads(acc_raw)
            if isinstance(parsed, list):
                acc_clean = [to_int(x) for x in parsed if to_int(x)]
        except Exception:
            pass
    # Créer une occupation par technicien
    created_ids = []
    for tid in tech_ids:
        # Retirer le tech lui-même de ses propres accompagnants pour cette occupation
        own_acc = [x for x in acc_clean if x != tid]
        acc_json = json.dumps(own_acc) if own_acc else ""
        db.execute("""INSERT INTO occupations
            (technicien_id, type_id, date, heure_debut, heure_fin, total_heures, notes, numero_projet, nom_chantier, accompagnants_ids)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (tid, type_id, date, heure_debut, heure_fin,
             total_heures, d.get("notes",""), numero_projet, nom_chantier, acc_json))
        created_ids.append(db.execute("SELECT last_insert_rowid()").fetchone()[0])
    db.commit()
    # Log : une entrée par occupation créée
    ot_info = one(db.execute("SELECT nom FROM occupation_types WHERE id=?", (type_id,)))
    ot_nom = (ot_info or {}).get("nom", "Occupation")
    for i, oid in enumerate(created_ids):
        tid = tech_ids[i] if i < len(tech_ids) else None
        t_info = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?", (tid,))) if tid else None
        label = f"{ot_nom} - {(t_info or {}).get('nom','?')} le {date}"
        log_action(request.user, "CREATE", "occupation", oid, label)
    # Retour : id du premier (compat) + liste complète
    return jsonify({"id": created_ids[0], "ids": created_ids, "count": len(created_ids)}), 201

@app.route("/api/occupations/<int:oid>", methods=["PATCH"])
@require_auth
def update_occupation(oid):
    d = request.json or {}
    u = request.user
    db = get_db()
    cur = one(db.execute("SELECT * FROM occupations WHERE id=?", (oid,)))
    if not cur: return jsonify({"error":"Introuvable"}), 404
    # Un tech ne peut modifier que ses propres occupations
    if u["role"] == "technicien" and cur.get("technicien_id") != u["id"]:
        return jsonify({"error":"Non autorisé"}), 403
    # Déterminer si le type final est "Offre" (pour valider numero_projet)
    final_type_id = to_int(d["type_id"]) if "type_id" in d else cur.get("type_id")
    is_offre = False
    if final_type_id:
        t = one(db.execute("SELECT nom FROM occupation_types WHERE id=?", (final_type_id,)))
        if t and (t.get("nom") or "").strip().lower() == "offre":
            is_offre = True
    # Valider / normaliser numero_projet et nom_chantier
    if is_offre:
        final_np = d["numero_projet"] if "numero_projet" in d else cur.get("numero_projet","")
        final_np = (final_np or "").strip()
        if not final_np:
            return jsonify({"error":"Numéro de projet requis pour une occupation de type Offre"}), 400
        if not re.match(r"^P\d{5}$", final_np):
            return jsonify({"error":"Le numéro de projet doit être au format P suivi de 5 chiffres (ex: P00042)"}), 400
        d["numero_projet"] = final_np
        final_nc = d["nom_chantier"] if "nom_chantier" in d else cur.get("nom_chantier","")
        final_nc = (final_nc or "").strip()
        if not final_nc:
            return jsonify({"error":"Nom du chantier requis pour une occupation de type Offre"}), 400
        d["nom_chantier"] = final_nc
    else:
        # Type non-Offre : on vide
        d["numero_projet"] = ""
        d["nom_chantier"] = ""
    # Normaliser accompagnants_ids : accepter liste d'ints, str JSON, ou chaîne "1,2,3"
    if "accompagnants_ids" in d:
        raw = d.get("accompagnants_ids")
        if raw is None or raw == "":
            d["accompagnants_ids"] = ""
        elif isinstance(raw, list):
            try:
                clean = [int(x) for x in raw if x is not None and str(x).strip() != ""]
                # Retirer le tech principal s'il est dedans
                tid_princ = to_int(d.get("technicien_id")) or cur.get("technicien_id")
                if tid_princ:
                    clean = [x for x in clean if x != tid_princ]
                d["accompagnants_ids"] = json.dumps(clean) if clean else ""
            except Exception:
                d["accompagnants_ids"] = ""
        elif isinstance(raw, str):
            # Peut être "[1,2]" JSON ou "1,2,3" CSV
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    clean = [int(x) for x in parsed if x is not None]
                    d["accompagnants_ids"] = json.dumps(clean) if clean else ""
                else:
                    d["accompagnants_ids"] = ""
            except Exception:
                try:
                    clean = [int(x.strip()) for x in raw.split(",") if x.strip()]
                    d["accompagnants_ids"] = json.dumps(clean) if clean else ""
                except Exception:
                    d["accompagnants_ids"] = ""
    sets, params = [], []
    for f in ["technicien_id", "type_id", "date", "heure_debut", "heure_fin", "notes", "numero_projet", "nom_chantier", "accompagnants_ids"]:
        if f in d:
            sets.append(f"{f}=?")
            # Champs int : technicien_id et type_id
            if f in ("technicien_id", "type_id"):
                params.append(to_int(d[f]))
            else:
                params.append(d[f])
    # Recalculer total_heures si horaires modifiés
    if "heure_debut" in d or "heure_fin" in d:
        hd = d.get("heure_debut", cur.get("heure_debut", ""))
        hf = d.get("heure_fin", cur.get("heure_fin", ""))
        sets.append("total_heures=?")
        params.append(_calc_heures(hd, hf))
    elif "total_heures" in d:
        sets.append("total_heures=?")
        try: params.append(float(d["total_heures"] or 0))
        except: params.append(0)
    if not sets: return jsonify({"error":"Rien"}), 400
    params.append(oid)
    db.execute(f"UPDATE occupations SET {chr(44).join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/occupations/<int:oid>", methods=["DELETE"])
@require_auth
def delete_occupation(oid):
    u = request.user; db = get_db()
    cur = one(db.execute("SELECT * FROM occupations WHERE id=?", (oid,)))
    if not cur: return jsonify({"error":"Introuvable"}), 404
    if u["role"] == "technicien" and cur.get("technicien_id") != u["id"]:
        return jsonify({"error":"Non autorisé"}), 403
    # Info pour log
    t_info = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?", (cur.get("technicien_id"),)))
    ot_info = one(db.execute("SELECT nom FROM occupation_types WHERE id=?", (cur.get("type_id"),)))
    label = f"{(ot_info or {}).get('nom','?')} - {(t_info or {}).get('nom','?')} le {cur.get('date','')}"
    db.execute("DELETE FROM occupations WHERE id=?", (oid,))
    db.commit()
    log_action(u, "DELETE", "occupation", oid, label)
    return jsonify({"ok": True})

# ══ POINTAGE MENSUEL (depuis les CR intervenants) ══
@app.route("/api/pointage/<int:annee>/<int:mois>")
@require_auth
def pointage_mensuel(annee, mois):
    """Agrège les heures de cr_intervenants pour un mois donné.
    Filtre facultatif : ?technicien_id=X (sinon tous)."""
    u = request.user
    db = get_db()
    tech_filter = request.args.get("technicien_id")
    # Les techniciens ne peuvent voir que leur propre pointage
    if u["role"] == "technicien":
        tech_filter = u["id"]
    # Période du mois (YYYY-MM-DD)
    from calendar import monthrange
    nb_jours = monthrange(annee, mois)[1]
    date_debut = f"{annee:04d}-{mois:02d}-01"
    date_fin = f"{annee:04d}-{mois:02d}-{nb_jours:02d}"
    # Requête de base
    sql = """SELECT ci.date, ci.heure_debut, ci.heure_fin, ci.total_heures,
                    ci.utilisateur_id, COALESCE(u.nom, ci.nom, 'Inconnu') AS nom_tech,
                    cr.id AS cr_id, cr.intervention_id,
                    i.numero AS num_bon, i.type AS type_bon,
                    e.designation AS equipement, p.nom AS projet,
                    p.numero_projet AS num_projet
             FROM cr_intervenants ci
             JOIN comptes_rendus cr ON ci.cr_id = cr.id
             JOIN interventions i ON cr.intervention_id = i.id
             JOIN equipements e ON i.equipement_id = e.id
             JOIN projets p ON e.projet_id = p.id
             LEFT JOIN utilisateurs u ON ci.utilisateur_id = u.id
             WHERE ci.date BETWEEN ? AND ?"""
    params = [date_debut, date_fin]
    if tech_filter:
        sql += " AND ci.utilisateur_id = ?"
        params.append(to_int(tech_filter))
    sql += " ORDER BY nom_tech, ci.date, ci.heure_debut"
    lignes = rows(db.execute(sql, params))
    # Marquer comme lignes d'intervention
    for l in lignes:
        l["source"] = "intervention"

    # Récupérer les occupations sur la même période
    sql_occ = """SELECT o.date, o.heure_debut, o.heure_fin, o.total_heures,
                        o.technicien_id AS utilisateur_id,
                        COALESCE(u.nom, 'Inconnu') AS nom_tech,
                        o.notes, o.numero_projet AS num_projet_occ,
                        o.nom_chantier,
                        ot.nom AS type_occupation, ot.couleur AS type_couleur
                 FROM occupations o
                 LEFT JOIN utilisateurs u ON o.technicien_id = u.id
                 LEFT JOIN occupation_types ot ON o.type_id = ot.id
                 WHERE o.date BETWEEN ? AND ?"""
    params_occ = [date_debut, date_fin]
    if tech_filter:
        sql_occ += " AND o.technicien_id = ?"
        params_occ.append(to_int(tech_filter))
    sql_occ += " ORDER BY nom_tech, o.date, o.heure_debut"
    occupations = rows(db.execute(sql_occ, params_occ))
    for o in occupations:
        o["source"] = "occupation"
        o["num_bon"] = ""
        o["type_bon"] = ""
        # Pour une occupation Offre → utiliser numero_projet saisi, sinon vide
        o["num_projet"] = o.get("num_projet_occ") or ""
        o["equipement"] = ""
        o["projet"] = o.get("type_occupation") or "Occupation"
        lignes.append(o)

    # Trier l'ensemble par tech/date/heure
    lignes.sort(key=lambda l: (l.get("nom_tech") or "", l.get("date") or "", l.get("heure_debut") or ""))

    # Totaux par technicien (incluant occupations)
    par_tech = {}
    for l in lignes:
        key = l.get("utilisateur_id") or l.get("nom_tech")
        if key not in par_tech:
            par_tech[key] = {
                "utilisateur_id": l.get("utilisateur_id"),
                "nom": l["nom_tech"],
                "total_heures": 0,
                "total_interventions_h": 0,
                "total_occupations_h": 0,
                "nb_jours": set(),
                "nb_interventions": set(),
            }
        h = float(l.get("total_heures") or 0)
        par_tech[key]["total_heures"] += h
        if l.get("source") == "occupation":
            par_tech[key]["total_occupations_h"] += h
        else:
            par_tech[key]["total_interventions_h"] += h
            if l.get("intervention_id"):
                par_tech[key]["nb_interventions"].add(l["intervention_id"])
        par_tech[key]["nb_jours"].add(l["date"])
    # Format JSON friendly
    totaux = [{
        "utilisateur_id": v["utilisateur_id"],
        "nom": v["nom"],
        "total_heures": round(v["total_heures"], 2),
        "total_interventions_h": round(v["total_interventions_h"], 2),
        "total_occupations_h": round(v["total_occupations_h"], 2),
        "nb_jours": len(v["nb_jours"]),
        "nb_interventions": len(v["nb_interventions"]),
    } for v in par_tech.values()]
    totaux.sort(key=lambda x: x["nom"])
    return jsonify({
        "annee": annee, "mois": mois,
        "date_debut": date_debut, "date_fin": date_fin,
        "lignes": lignes, "totaux": totaux,
    })

@app.route("/api/pointage/<int:annee>/<int:mois>/export")
@require_role("admin","manager")
def pointage_export(annee, mois):
    """Export Excel du pointage mensuel."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from flask import make_response
    db = get_db()
    from calendar import monthrange
    nb_jours = monthrange(annee, mois)[1]
    date_debut = f"{annee:04d}-{mois:02d}-01"
    date_fin = f"{annee:04d}-{mois:02d}-{nb_jours:02d}"
    lignes = rows(db.execute("""
        SELECT ci.date, ci.heure_debut, ci.heure_fin, ci.total_heures,
               COALESCE(u.nom, ci.nom, 'Inconnu') AS nom_tech,
               i.numero AS num_bon, i.type AS type_bon,
               e.designation AS equipement, p.nom AS projet,
               p.numero_projet AS num_projet
        FROM cr_intervenants ci
        JOIN comptes_rendus cr ON ci.cr_id = cr.id
        JOIN interventions i ON cr.intervention_id = i.id
        JOIN equipements e ON i.equipement_id = e.id
        JOIN projets p ON e.projet_id = p.id
        LEFT JOIN utilisateurs u ON ci.utilisateur_id = u.id
        WHERE ci.date BETWEEN ? AND ?
        ORDER BY nom_tech, ci.date, ci.heure_debut
    """, [date_debut, date_fin]))
    for l in lignes: l["source"] = "intervention"

    # Occupations sur la période
    occupations = rows(db.execute("""
        SELECT o.date, o.heure_debut, o.heure_fin, o.total_heures,
               COALESCE(u.nom, 'Inconnu') AS nom_tech,
               o.notes, o.numero_projet AS num_projet_occ,
               o.nom_chantier,
               ot.nom AS type_occupation
        FROM occupations o
        LEFT JOIN utilisateurs u ON o.technicien_id = u.id
        LEFT JOIN occupation_types ot ON o.type_id = ot.id
        WHERE o.date BETWEEN ? AND ?
        ORDER BY nom_tech, o.date, o.heure_debut
    """, [date_debut, date_fin]))
    for o in occupations:
        o["source"] = "occupation"
        o["num_bon"] = ""
        o["type_bon"] = o.get("type_occupation") or "Occupation"
        # Offre → numero_projet saisi à la place du N° Projet classique
        o["num_projet"] = o.get("num_projet_occ") or ""
        o["equipement"] = ""
        # Pour le projet, afficher le nom du chantier si présent (offre), sinon notes/type
        o["projet"] = o.get("nom_chantier") or o.get("notes") or o.get("type_occupation") or ""
    all_lignes = lignes + occupations
    all_lignes.sort(key=lambda l: (l.get("nom_tech") or "", l.get("date") or "", l.get("heure_debut") or ""))

    wb = Workbook()
    # ── Feuille 1 : Détail ──
    ws = wb.active
    ws.title = "Détail"
    headers = ["Technicien", "Date", "Début", "Fin", "Total h", "Catégorie", "N° Bon", "Type", "N° Projet", "Équipement", "Projet / Notes"]
    head_font = Font(bold=True, color="FFFFFF")
    head_fill = PatternFill("solid", fgColor="0F1E3D")
    occ_fill = PatternFill("solid", fgColor="FEF3C7")  # fond jaune pâle pour occupations
    thin = Side(border_style="thin", color="D0D0D0")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for i, h in enumerate(headers, 1):
        c = ws.cell(row=1, column=i, value=h)
        c.font = head_font; c.fill = head_fill
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = border
    for idx, l in enumerate(all_lignes, 2):
        is_occ = l.get("source") == "occupation"
        row_data = [
            l["nom_tech"], l["date"], l.get("heure_debut",""), l.get("heure_fin",""),
            float(l.get("total_heures") or 0),
            "Occupation" if is_occ else "Intervention",
            l.get("num_bon",""), l.get("type_bon",""),
            l.get("num_projet",""),
            l.get("equipement",""), l.get("projet","")
        ]
        for ci, v in enumerate(row_data, 1):
            c = ws.cell(row=idx, column=ci, value=v)
            c.border = border
            if is_occ: c.fill = occ_fill
    # Largeurs
    widths = [22, 12, 8, 8, 10, 12, 14, 14, 14, 30, 30]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[chr(64+i)].width = w
    ws.freeze_panes = "A2"
    # ── Feuille 2 : Totaux ──
    ws2 = wb.create_sheet("Totaux")
    headers2 = ["Technicien", "Total heures", "dont Interventions", "dont Occupations", "Nb jours travaillés", "Nb interventions"]
    for i, h in enumerate(headers2, 1):
        c = ws2.cell(row=1, column=i, value=h)
        c.font = head_font; c.fill = head_fill
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = border
    # Agrégation
    par_tech = {}
    for l in all_lignes:
        key = l["nom_tech"]
        if key not in par_tech:
            par_tech[key] = {"nom": key, "total": 0, "interv_h": 0, "occ_h": 0, "jours": set(), "bons": set()}
        h = float(l.get("total_heures") or 0)
        par_tech[key]["total"] += h
        if l.get("source") == "occupation":
            par_tech[key]["occ_h"] += h
        else:
            par_tech[key]["interv_h"] += h
            if l.get("num_bon"): par_tech[key]["bons"].add(l["num_bon"])
        par_tech[key]["jours"].add(l["date"])
    for idx, (nom, v) in enumerate(sorted(par_tech.items()), 2):
        row_data = [v["nom"], round(v["total"],2), round(v["interv_h"],2), round(v["occ_h"],2),
                    len(v["jours"]), len(v["bons"])]
        for ci, val in enumerate(row_data, 1):
            c = ws2.cell(row=idx, column=ci, value=val)
            c.border = border
            if ci == 2: c.font = Font(bold=True)
    for i, w in enumerate([22, 14, 16, 16, 20, 18], 1):
        ws2.column_dimensions[chr(64+i)].width = w
    ws2.freeze_panes = "A2"
    # ── Feuille 3 : Occupations ──
    ws3 = wb.create_sheet("Occupations")
    headers3 = ["Technicien", "Date", "Début", "Fin", "Total h", "Type", "N° Projet", "Nom du chantier", "Notes"]
    for i, h in enumerate(headers3, 1):
        c = ws3.cell(row=1, column=i, value=h)
        c.font = head_font; c.fill = head_fill
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = border
    for idx, o in enumerate(occupations, 2):
        row_data = [
            o["nom_tech"], o["date"], o.get("heure_debut",""), o.get("heure_fin",""),
            float(o.get("total_heures") or 0),
            o.get("type_occupation",""),
            o.get("num_projet_occ","") or o.get("num_projet",""),
            o.get("nom_chantier",""),
            o.get("notes","")
        ]
        for ci, v in enumerate(row_data, 1):
            c = ws3.cell(row=idx, column=ci, value=v)
            c.border = border
    for i, w in enumerate([22, 12, 8, 8, 10, 18, 14, 30, 40], 1):
        ws3.column_dimensions[chr(64+i)].width = w
    ws3.freeze_panes = "A2"
    # Sortie
    buf = io.BytesIO()
    wb.save(buf); buf.seek(0)
    fname = f"Pointage_{annee:04d}-{mois:02d}.xlsx"
    resp = make_response(buf.read())
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp

# ══ POINTAGE HEBDOMADAIRE ══

def _iso_week_dates(annee, semaine):
    """Retourne (lundi, dimanche) datetime.date de la semaine ISO donnée."""
    from datetime import date, timedelta
    # Le 4 janvier est toujours dans la semaine 1 (standard ISO)
    jan4 = date(annee, 1, 4)
    # Lundi de la semaine 1
    w1_mon = jan4 - timedelta(days=jan4.weekday())
    mon = w1_mon + timedelta(weeks=semaine - 1)
    sun = mon + timedelta(days=6)
    return mon, sun

@app.route("/api/pointage/week/<int:annee>/<int:semaine>")
@require_auth
def pointage_hebdo(annee, semaine):
    """Agrège les heures d'une semaine donnée. Par technicien et par projet/jour."""
    u = request.user
    db = get_db()
    try:
        mon, sun = _iso_week_dates(annee, semaine)
    except Exception:
        return jsonify({"error":"Semaine invalide"}), 400
    date_debut = mon.strftime("%Y-%m-%d")
    date_fin = sun.strftime("%Y-%m-%d")
    tech_filter = request.args.get("technicien_id")
    if u["role"] == "technicien":
        tech_filter = u["id"]
    # Lignes interventions (via cr_intervenants)
    sql = """SELECT ci.date, ci.heure_debut, ci.heure_fin, ci.total_heures,
                    ci.utilisateur_id, COALESCE(u.nom, ci.nom, 'Inconnu') AS nom_tech,
                    cr.id AS cr_id, cr.intervention_id,
                    i.numero AS num_bon, i.type AS type_bon,
                    e.designation AS equipement, p.nom AS projet,
                    p.numero_projet AS num_projet
             FROM cr_intervenants ci
             JOIN comptes_rendus cr ON ci.cr_id = cr.id
             JOIN interventions i ON cr.intervention_id = i.id
             JOIN equipements e ON i.equipement_id = e.id
             JOIN projets p ON e.projet_id = p.id
             LEFT JOIN utilisateurs u ON ci.utilisateur_id = u.id
             WHERE ci.date BETWEEN ? AND ?"""
    params = [date_debut, date_fin]
    if tech_filter:
        sql += " AND ci.utilisateur_id = ?"
        params.append(to_int(tech_filter))
    sql += " ORDER BY nom_tech, ci.date, ci.heure_debut"
    lignes = rows(db.execute(sql, params))
    for l in lignes:
        l["source"] = "intervention"

    # Occupations sur la période
    sql_occ = """SELECT o.date, o.heure_debut, o.heure_fin, o.total_heures,
                        o.technicien_id AS utilisateur_id,
                        COALESCE(u.nom, 'Inconnu') AS nom_tech,
                        o.notes, o.numero_projet AS num_projet_occ, o.nom_chantier,
                        ot.nom AS type_occupation, ot.couleur AS type_couleur
                 FROM occupations o
                 LEFT JOIN utilisateurs u ON o.technicien_id = u.id
                 LEFT JOIN occupation_types ot ON o.type_id = ot.id
                 WHERE o.date BETWEEN ? AND ?"""
    params_occ = [date_debut, date_fin]
    if tech_filter:
        sql_occ += " AND o.technicien_id = ?"
        params_occ.append(to_int(tech_filter))
    sql_occ += " ORDER BY nom_tech, o.date, o.heure_debut"
    occupations = rows(db.execute(sql_occ, params_occ))
    for o in occupations:
        o["source"] = "occupation"
        o["num_bon"] = ""
        o["type_bon"] = ""
        o["num_projet"] = o.get("num_projet_occ") or ""
        o["equipement"] = ""
        o["projet"] = o.get("nom_chantier") or o.get("type_occupation") or ""
        lignes.append(o)

    lignes.sort(key=lambda l: (l.get("nom_tech") or "", l.get("date") or "", l.get("heure_debut") or ""))

    # Totaux par technicien
    par_tech = {}
    for l in lignes:
        key = l.get("utilisateur_id") or l.get("nom_tech")
        if key not in par_tech:
            par_tech[key] = {
                "utilisateur_id": l.get("utilisateur_id"),
                "nom": l["nom_tech"],
                "total_heures": 0,
                "total_interventions_h": 0,
                "total_occupations_h": 0,
                "nb_jours": set(),
                "nb_interventions": set(),
            }
        h = float(l.get("total_heures") or 0)
        par_tech[key]["total_heures"] += h
        if l.get("source") == "occupation":
            par_tech[key]["total_occupations_h"] += h
        else:
            par_tech[key]["total_interventions_h"] += h
            if l.get("intervention_id"):
                par_tech[key]["nb_interventions"].add(l["intervention_id"])
        par_tech[key]["nb_jours"].add(l["date"])
    totaux = [{
        "utilisateur_id": v["utilisateur_id"],
        "nom": v["nom"],
        "total_heures": round(v["total_heures"], 2),
        "total_interventions_h": round(v["total_interventions_h"], 2),
        "total_occupations_h": round(v["total_occupations_h"], 2),
        "nb_jours": len(v["nb_jours"]),
        "nb_interventions": len(v["nb_interventions"]),
    } for v in par_tech.values()]
    totaux.sort(key=lambda x: x["nom"])
    return jsonify({
        "annee": annee, "semaine": semaine,
        "date_debut": date_debut, "date_fin": date_fin,
        "lignes": lignes, "totaux": totaux,
    })


@app.route("/api/pointage/week/<int:annee>/<int:semaine>/<int:technicien_id>/fiche")
@require_role("admin","manager")
def pointage_fiche_hebdo(annee, semaine, technicien_id):
    """Génère une fiche de pointage Excel hebdomadaire pour un technicien,
    en utilisant le template pointage_template.xlsx."""
    from openpyxl import load_workbook
    from flask import make_response
    db = get_db()
    try:
        mon, sun = _iso_week_dates(annee, semaine)
    except Exception:
        return jsonify({"error":"Semaine invalide"}), 400
    # Récupérer le technicien + son manager
    tech = one(db.execute("SELECT * FROM utilisateurs WHERE id=?", (technicien_id,)))
    if not tech:
        return jsonify({"error":"Technicien introuvable"}), 404
    logger.info(f"[FICHE] tech_id={technicien_id} nom={tech.get('nom')} matricule={repr(tech.get('matricule'))} manager_id={tech.get('manager_id')}")
    date_debut = mon.strftime("%Y-%m-%d")
    date_fin = sun.strftime("%Y-%m-%d")
    # Localiser le template
    tpl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pointage_template.xlsx")
    if not os.path.exists(tpl_path):
        return jsonify({"error":"Template introuvable"}), 500
    wb = load_workbook(tpl_path)
    ws = wb.active
    # Remplir en-tête
    ws["B5"] = semaine
    from datetime import datetime as _dt
    ws["G14"] = _dt(mon.year, mon.month, mon.day)  # formules Excel calculent les 6 autres jours
    ws["B7"] = tech.get("nom","")
    # Matricule : on tente d'abord l'entier (cohérent avec le template), sinon string
    mat_raw = (tech.get("matricule") or "").strip() if isinstance(tech.get("matricule"), str) else tech.get("matricule")
    if mat_raw:
        try:
            ws["I7"] = int(str(mat_raw).strip())
        except (ValueError, TypeError):
            ws["I7"] = str(mat_raw).strip()
    else:
        ws["I7"] = ""
    # Manager : récupérer depuis le lien manager_id du technicien
    mgr_nom = ""
    if tech.get("manager_id"):
        mgr = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?", (tech.get("manager_id"),)))
        if mgr:
            mgr_nom = mgr.get("nom","") or ""
    logger.info(f"[FICHE] mgr_nom={repr(mgr_nom)} I7={repr(ws['I7'].value)}")
    ws["V7"] = mgr_nom
    # Bloc signature manager (B35)
    ws["B35"] = mgr_nom
    # Effacer les lignes exemples (16..32) pour les colonnes projet/données
    for row in range(16, 33):
        for col_letter in ['A','B','C','E','F','G','H','I','J','K','L','M','N',
                            'O','P','Q','R','S','T','U','V','W','X','Y','Z','AA']:
            coord = f'{col_letter}{row}'
            ws[coord] = None
    # Récupérer les CR+intervenants de la semaine pour ce tech
    cr_rows = rows(db.execute("""
        SELECT ci.date, ci.total_heures,
               i.numero AS num_bon, i.type AS type_bon,
               e.designation AS equipement, p.nom AS projet,
               p.numero_projet AS num_projet
        FROM cr_intervenants ci
        JOIN comptes_rendus cr ON ci.cr_id = cr.id
        JOIN interventions i ON cr.intervention_id = i.id
        JOIN equipements e ON i.equipement_id = e.id
        JOIN projets p ON e.projet_id = p.id
        WHERE ci.date BETWEEN ? AND ? AND ci.utilisateur_id = ?
        ORDER BY ci.date
    """, (date_debut, date_fin, technicien_id)))
    # Occupations de la semaine pour ce tech
    occ_rows = rows(db.execute("""
        SELECT o.date, o.heure_debut, o.heure_fin, o.total_heures,
               o.notes, o.numero_projet, o.nom_chantier,
               ot.nom AS type_nom
        FROM occupations o
        LEFT JOIN occupation_types ot ON o.type_id = ot.id
        WHERE o.date BETWEEN ? AND ? AND o.technicien_id = ?
        ORDER BY o.date
    """, (date_debut, date_fin, technicien_id)))
    # Construire une structure : clé (num_projet, nom_projet, num_bon) -> {jour_idx: {heures, code}}
    # jours_idx : 0=lundi, 1=mardi, ..., 6=dimanche
    # Mapping vers colonnes Excel :
    #   L (lundi) = F (heures), G (nuit), H (code)
    #   M (mardi) = I, J, K
    #   M (mercr) = L, M, N
    #   J (jeudi) = O, P, Q
    #   V (vendr) = R, S, T
    #   S (samed) = U, V, W
    #   D (dim)   = X, Y, Z
    jour_cols = [
        ('F','G','H'),  # lundi
        ('I','J','K'),  # mardi
        ('L','M','N'),  # mercredi
        ('O','P','Q'),  # jeudi
        ('R','S','T'),  # vendredi
        ('U','V','W'),  # samedi
        ('X','Y','Z'),  # dimanche
    ]
    # Mapping code occupation → lettre code à utiliser dans la colonne Co
    # Selon la légende du modèle : C=Congé, CX=Congé exceptionnel, E=École, M=Maladie,
    # AT=Accident, F=Férié, AM=Absence motivée, A=Absence non motivée,
    # RF=Récup férié, RC=Récup compteur, FO=Formation
    code_map = {
        "congés": "C", "conges": "C", "congé": "C",
        "formation": "FO",
        "maladie": "M",
        "rtt": "RC",
        "réunion": None, "reunion": None,  # pas de code prévu pour réunion, laisser vide
        "école": "E", "ecole": "E",
        "férié": "F", "ferie": "F",
        "accident": "AT",
    }
    # Regrouper : {(num_projet, nom_projet, num_bon): {jour_idx: (heures, code)}}
    groupes = {}
    def _add(num_p, nom_p, num_b, jidx, h, code):
        k = (num_p or "", nom_p or "", num_b or "")
        if k not in groupes:
            groupes[k] = {}
        existing = groupes[k].get(jidx, (0, ""))
        new_h = (existing[0] or 0) + (h or 0)
        new_code = code or existing[1]
        groupes[k][jidx] = (new_h, new_code)
    # Interventions
    for r in cr_rows:
        try:
            d = _dt.strptime(r["date"][:10], "%Y-%m-%d").date()
            jidx = (d - mon).days
            if 0 <= jidx <= 6:
                _add(r.get("num_projet"), r.get("projet"), r.get("num_bon"), jidx, r.get("total_heures") or 0, "")
        except Exception:
            continue
    # Occupations
    for o in occ_rows:
        try:
            d = _dt.strptime(o["date"][:10], "%Y-%m-%d").date()
            jidx = (d - mon).days
            if 0 <= jidx <= 6:
                t_nom = (o.get("type_nom") or "").strip().lower()
                code = code_map.get(t_nom, "")
                num_p = o.get("numero_projet") or ""
                nom_p = o.get("nom_chantier") or o.get("type_nom") or "Occupation"
                _add(num_p, nom_p, "/", jidx, o.get("total_heures") or 0, code)
        except Exception:
            continue
    # Écrire dans le fichier : une ligne par groupe, à partir de la ligne 16, max 17 lignes (16..32)
    current_row = 16
    max_row = 32
    # Matricule formaté pour colonne E (int si numérique, sinon string)
    mat_raw2 = tech.get("matricule") or ""
    try:
        mat_id = int(str(mat_raw2).strip()) if str(mat_raw2).strip() else ""
    except (ValueError, TypeError):
        mat_id = str(mat_raw2).strip()
    for (num_p, nom_p, num_b), jours in sorted(groupes.items()):
        if current_row > max_row:
            break
        ws[f"A{current_row}"] = num_p
        ws[f"B{current_row}"] = nom_p
        ws[f"C{current_row}"] = num_b
        ws[f"E{current_row}"] = mat_id
        for jidx, (hh, code) in jours.items():
            hrs_col, hn_col, co_col = jour_cols[jidx]
            if hh:
                ws[f"{hrs_col}{current_row}"] = hh
            if code:
                ws[f"{co_col}{current_row}"] = code
        current_row += 1
    # Les formules SUM(F16:F32) etc + AA33 = total général sont déjà dans le template.
    # Sortie
    buf = io.BytesIO()
    wb.save(buf); buf.seek(0)
    # Nom du fichier
    mois_noms = ["Janvier","Février","Mars","Avril","Mai","Juin","Juillet","Août","Septembre","Octobre","Novembre","Décembre"]
    mois_nom = mois_noms[mon.month - 1]
    nom_safe = re.sub(r'[^A-Za-z0-9_-]', '_', tech.get("nom","Technicien"))
    fname = f"Pointage_{mois_nom}_S{semaine:02d}_{annee}_{nom_safe}.xlsx"
    resp = make_response(buf.read())
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp

# ══ PLANNING TECHNICIEN (vue unifiée créneaux + interventions) ══
@app.route("/api/planning/me")
@require_auth
def planning_me():
    """Retourne le planning d'un technicien sur une période.
    Combine les créneaux multi-jours et les interventions à date unique.
    Paramètres : ?debut=YYYY-MM-DD&fin=YYYY-MM-DD&technicien_id=X (admin/manager seulement)

    Un admin voit n'importe quel technicien. Un manager peut voir son équipe
    (les techniciens dont manager_id = son id) + lui-même.
    Un technicien ne peut voir que son propre planning."""
    u = request.user
    db = get_db()
    debut = request.args.get("debut")
    fin = request.args.get("fin")
    if not debut or not fin:
        return jsonify({"error":"debut et fin requis"}), 400
    # Déterminer le technicien cible
    target_id = u["id"]
    req_tid = request.args.get("technicien_id")
    if req_tid:
        req_tid = to_int(req_tid)
        if req_tid and req_tid != u["id"]:
            # Admin : accès à tout le monde
            if u["role"] == "admin":
                target_id = req_tid
            # Manager : accès seulement à son équipe
            elif u["role"] == "manager":
                target = one(db.execute("SELECT manager_id FROM utilisateurs WHERE id=?", (req_tid,)))
                if target and target.get("manager_id") == u["id"]:
                    target_id = req_tid
                else:
                    return jsonify({"error":"Technicien non autorisé (pas de votre équipe)"}), 403
            else:
                # Un technicien ne peut pas consulter un autre tech
                return jsonify({"error":"Non autorisé"}), 403
    items = []
    # Créneaux planifiés explicitement pour ce technicien
    # OU créneaux d'interventions dont ce technicien est multi-tech (pour voir le bon même si le créneau est assigné à un collègue)
    creneaux = rows(db.execute("""
        SELECT c.id AS creneau_id, c.date, c.heure_debut, c.heure_fin, c.notes,
               i.id AS intervention_id, i.numero, i.type, i.statut, i.description,
               e.designation AS equip_nom, e.type_technique,
               p.nom AS projet_nom
        FROM intervention_creneaux c
        JOIN interventions i ON c.intervention_id = i.id
        JOIN equipements e ON i.equipement_id = e.id
        JOIN projets p ON e.projet_id = p.id
        WHERE (
               c.technicien_id = ?
               OR (
                  (c.technicien_id IS NULL OR c.technicien_id = 0)
                  AND (i.technicien_id = ? OR EXISTS (
                       SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND it.utilisateur_id=?))
               )
               OR EXISTS (
                  SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND it.utilisateur_id=?
               )
        )
        AND c.date BETWEEN ? AND ?
        AND i.statut != 'ANNULEE'
        ORDER BY c.date, c.heure_debut
    """, (target_id, target_id, target_id, target_id, debut, fin)))
    for c in creneaux:
        c["source"] = "creneau"
        items.append(c)
    # Interventions sans aucun créneau, assignées au technicien sur la période
    ivs = rows(db.execute("""
        SELECT i.id AS intervention_id, i.numero, i.type, i.statut, i.description,
               i.date_prevue AS date, i.heure_prevue AS heure_debut,
               e.designation AS equip_nom, e.type_technique,
               p.nom AS projet_nom
        FROM interventions i
        JOIN equipements e ON i.equipement_id = e.id
        JOIN projets p ON e.projet_id = p.id
        WHERE (i.technicien_id = ? OR EXISTS (
              SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND it.utilisateur_id=?))
          AND i.date_prevue BETWEEN ? AND ?
          AND i.statut != 'ANNULEE'
          AND NOT EXISTS (SELECT 1 FROM intervention_creneaux c WHERE c.intervention_id = i.id)
        ORDER BY i.date_prevue, i.heure_prevue
    """, (target_id, target_id, debut, fin)))
    for iv in ivs:
        iv["source"] = "intervention"
        iv["heure_fin"] = ""
        iv["creneau_id"] = None
        iv["notes"] = ""
        items.append(iv)
    # Si c'est un manager technique consultant SON propre planning :
    # ajouter les interventions liées aux techniques qu'il gère (même si non assignées à lui)
    if target_id == u["id"] and u["role"] == "manager":
        udb = one(db.execute("SELECT techniques FROM utilisateurs WHERE id=?", (u["id"],)))
        tech_csv = (udb and udb.get("techniques")) or ""
        tech_list = [t.strip() for t in tech_csv.split(",") if t.strip()]
        if tech_list:
            placeholders = ",".join(["?"] * len(tech_list))
            # Éviter les doublons : exclure les interventions déjà ajoutées
            existing_iv_ids = {it.get("intervention_id") for it in items if it.get("intervention_id")}
            # Créneaux liés aux techniques (tous, peu importe l'assignation)
            mgr_creneaux = rows(db.execute(f"""
                SELECT c.id AS creneau_id, c.date, c.heure_debut, c.heure_fin, c.notes,
                       i.id AS intervention_id, i.numero, i.type, i.statut, i.description,
                       e.designation AS equip_nom, e.type_technique,
                       p.nom AS projet_nom
                FROM intervention_creneaux c
                JOIN interventions i ON c.intervention_id = i.id
                JOIN equipements e ON i.equipement_id = e.id
                JOIN projets p ON e.projet_id = p.id
                WHERE e.type_technique IN ({placeholders})
                  AND c.date BETWEEN ? AND ?
                  AND i.statut != 'ANNULEE'
                ORDER BY c.date, c.heure_debut
            """, tech_list + [debut, fin]))
            for c in mgr_creneaux:
                # Éviter doublon avec les créneaux déjà ajoutés (via creneau_id)
                if not any(it.get("source")=="creneau" and it.get("creneau_id")==c["creneau_id"] for it in items):
                    c["source"] = "creneau"
                    items.append(c)
            # Interventions sans créneau, liées aux techniques
            mgr_ivs = rows(db.execute(f"""
                SELECT i.id AS intervention_id, i.numero, i.type, i.statut, i.description,
                       i.date_prevue AS date, i.heure_prevue AS heure_debut,
                       e.designation AS equip_nom, e.type_technique,
                       p.nom AS projet_nom
                FROM interventions i
                JOIN equipements e ON i.equipement_id = e.id
                JOIN projets p ON e.projet_id = p.id
                WHERE e.type_technique IN ({placeholders})
                  AND i.date_prevue BETWEEN ? AND ?
                  AND i.statut != 'ANNULEE'
                  AND NOT EXISTS (SELECT 1 FROM intervention_creneaux cc WHERE cc.intervention_id = i.id)
                ORDER BY i.date_prevue, i.heure_prevue
            """, tech_list + [debut, fin]))
            for iv in mgr_ivs:
                if iv["intervention_id"] not in existing_iv_ids:
                    iv["source"] = "intervention"
                    iv["heure_fin"] = ""
                    iv["creneau_id"] = None
                    iv["notes"] = ""
                    items.append(iv)
    # Occupations (congés, formation, etc.) du technicien cible
    occs = rows(db.execute("""
        SELECT o.id AS occupation_id, o.date, o.heure_debut, o.heure_fin, o.notes,
               o.type_id, ot.nom AS type_occupation, ot.couleur AS type_couleur,
               o.total_heures, o.numero_projet, o.nom_chantier, o.accompagnants_ids
        FROM occupations o
        LEFT JOIN occupation_types ot ON o.type_id = ot.id
        WHERE o.technicien_id = ? AND o.date BETWEEN ? AND ?
        ORDER BY o.date, o.heure_debut
    """, (target_id, debut, fin)))
    # Résoudre les accompagnants en noms pour l'affichage
    _resolve_accompagnants(db, occs)
    for o in occs:
        o["source"] = "occupation"
        # Pour cohérence avec les clés attendues par le mobile
        o["intervention_id"] = None
        o["numero"] = ""
        o["type"] = "OCCUPATION"
        o["statut"] = ""
        o["description"] = o.get("notes") or ""
        o["equip_nom"] = o.get("type_occupation") or "Occupation"
        o["projet_nom"] = ""
        items.append(o)

    # ═══════════════════════════════════════════════════════════════════
    # REMPLACEMENT DES BONS PAR LEURS CRs
    # Pour chaque intervention (MAINTENANCE ou DEPANNAGE) ayant au moins un CR,
    # on retire les items issus du bon et on les remplace par des pseudo-items
    # représentant les CRs (un par CR, à la date/heure du CR).
    # Règle :
    #   - MAINTENANCE sans CR → on garde le bon (affiché comme avant)
    #   - MAINTENANCE avec CR(s) → on remplace par les CR(s)
    #   - DEPANNAGE sans CR → on garde le bon
    #   - DEPANNAGE avec CR(s) → on remplace par les CR(s)
    # On charge les CRs pour TOUTES les interventions liées aux items du planning,
    # MAIS aussi pour toutes les interventions qui ont un CR dans la plage de dates affichée
    # (permet de capter les CRs dont la date diffère de la date_prevue du bon parent).
    # ═══════════════════════════════════════════════════════════════════
    try:
        # 1) Interventions déjà présentes dans les items
        intervention_ids = set(it.get("intervention_id") for it in items if it.get("intervention_id"))
        logger.info(f"[planning_me] target_id={target_id} debut={debut} fin={fin} items_before={len(items)} iv_ids_from_items={intervention_ids}")
        # 2) Interventions dont un CR tombe dans la fenêtre debut/fin
        # On regarde soit la date_intervention du CR, soit la date spécifique de l'intervenant
        # (qui peut différer en cas de CR multi-jours ou multi-intervenants)
        crs_in_range = rows(db.execute(
            """SELECT DISTINCT cr.intervention_id
               FROM comptes_rendus cr
               JOIN cr_intervenants ci ON ci.cr_id = cr.id
               WHERE ci.utilisateur_id = ?
                 AND (
                      (cr.date_intervention BETWEEN ? AND ?)
                   OR (NULLIF(ci.date,'') BETWEEN ? AND ?)
                 )""",
            (target_id, debut, fin, debut, fin)
        ))
        logger.info(f"[planning_me] crs_in_range={crs_in_range}")
        for row in crs_in_range:
            if row.get("intervention_id"):
                intervention_ids.add(row["intervention_id"])
        logger.info(f"[planning_me] intervention_ids_final={intervention_ids}")

        if intervention_ids:
            iid_list = list(intervention_ids)
            placeholders = ",".join(["?"] * len(iid_list))
            all_crs = rows(db.execute(
                f"SELECT id, intervention_id, numero, date_intervention FROM comptes_rendus WHERE intervention_id IN ({placeholders}) ORDER BY date_intervention, id",
                iid_list
            ))
            crs_by_iv = {}
            for cr in all_crs:
                crs_by_iv.setdefault(cr["intervention_id"], []).append(cr)
            # Charger horaires + intervenants pour chaque CR
            # + date spécifique du technicien cible (table cr_intervenants a sa propre date)
            for cr in all_crs:
                try:
                    horaires = one(db.execute(
                        """SELECT MIN(NULLIF(heure_debut,'')) AS h_min, MAX(NULLIF(heure_fin,'')) AS h_max
                           FROM cr_intervenants WHERE cr_id=?""", (cr["id"],)))
                    cr["heure_debut"] = (horaires or {}).get("h_min") or ""
                    cr["heure_fin"] = (horaires or {}).get("h_max") or ""
                except Exception:
                    cr["heure_debut"] = ""
                    cr["heure_fin"] = ""
                try:
                    tech_rows = rows(db.execute(
                        "SELECT DISTINCT utilisateur_id FROM cr_intervenants WHERE cr_id=? AND utilisateur_id IS NOT NULL",
                        (cr["id"],)))
                    cr["technicien_ids"] = [t["utilisateur_id"] for t in tech_rows if t.get("utilisateur_id")]
                except Exception:
                    cr["technicien_ids"] = []
                # Date + horaires spécifiques pour ce technicien cible (précise la date en cas de CR multi-jours)
                try:
                    my_row = one(db.execute(
                        """SELECT date, heure_debut, heure_fin FROM cr_intervenants
                           WHERE cr_id=? AND utilisateur_id=?
                           ORDER BY id LIMIT 1""",
                        (cr["id"], target_id)))
                    if my_row:
                        my_date = (my_row.get("date") or "").strip()
                        my_hd = (my_row.get("heure_debut") or "").strip()
                        my_hf = (my_row.get("heure_fin") or "").strip()
                        if my_date:
                            cr["date_for_target"] = my_date[:10]
                        if my_hd:
                            cr["heure_debut"] = my_hd
                        if my_hf:
                            cr["heure_fin"] = my_hf
                except Exception:
                    pass
                # Fallback : date_intervention du CR si pas de date intervenant spécifique
                if not cr.get("date_for_target"):
                    cr["date_for_target"] = (cr.get("date_intervention") or "")[:10]
                logger.info(f"[planning_me] CR {cr.get('numero')} (id={cr['id']}) iv={cr['intervention_id']} date_cr={cr.get('date_intervention')} date_target={cr.get('date_for_target')} hd={cr.get('heure_debut')} hf={cr.get('heure_fin')} techs={cr.get('technicien_ids')}")
            ivs_with_crs = set(crs_by_iv.keys())
            # Indexer métadonnées bons parents — d'abord via items, sinon requête directe
            iv_meta = {}
            for it in items:
                iid = it.get("intervention_id")
                if iid and iid in ivs_with_crs and iid not in iv_meta:
                    iv_meta[iid] = {
                        "numero": it.get("numero"),
                        "type": it.get("type"),
                        "statut": it.get("statut"),
                        "description": it.get("description"),
                        "equip_nom": it.get("equip_nom"),
                        "type_technique": it.get("type_technique"),
                        "projet_nom": it.get("projet_nom"),
                    }
            # Pour les interventions découvertes via les CRs mais pas dans items → requête directe
            missing_meta = [iid for iid in ivs_with_crs if iid not in iv_meta]
            if missing_meta:
                mm_ph = ",".join(["?"] * len(missing_meta))
                missing_rows = rows(db.execute(
                    f"""SELECT i.id AS intervention_id, i.numero, i.type, i.statut, i.description,
                               e.designation AS equip_nom, e.type_technique,
                               p.nom AS projet_nom
                       FROM interventions i
                       JOIN equipements e ON i.equipement_id = e.id
                       JOIN projets p ON e.projet_id = p.id
                       WHERE i.id IN ({mm_ph})""",
                    missing_meta
                ))
                for r in missing_rows:
                    iv_meta[r["intervention_id"]] = {
                        "numero": r.get("numero"),
                        "type": r.get("type"),
                        "statut": r.get("statut"),
                        "description": r.get("description"),
                        "equip_nom": r.get("equip_nom"),
                        "type_technique": r.get("type_technique"),
                        "projet_nom": r.get("projet_nom"),
                    }
            # Retirer tous les items dont l'intervention a au moins un CR
            items = [it for it in items if not (it.get("intervention_id") in ivs_with_crs)]
            # Ajouter les pseudo-items CR (uniquement ceux où le technicien cible est intervenant)
            for iid, crs in crs_by_iv.items():
                meta = iv_meta.get(iid, {})
                for cr in crs:
                    cr_date = cr.get("date_for_target") or (cr.get("date_intervention") or "")[:10]
                    # Filtrer : tech cible intervenant ET date dans la fenêtre
                    if target_id not in cr.get("technicien_ids", []):
                        continue
                    if cr_date < debut or cr_date > fin:
                        continue
                    items.append({
                        "source": "cr",
                        "cr_id": cr["id"],
                        "cr_numero": cr.get("numero") or "",
                        "intervention_id": iid,
                        "creneau_id": None,
                        "date": cr_date,
                        "heure_debut": cr.get("heure_debut") or "",
                        "heure_fin": cr.get("heure_fin") or "",
                        "notes": "",
                        "numero": meta.get("numero") or "",
                        "type": meta.get("type") or "",
                        "statut": meta.get("statut") or "",
                        "description": meta.get("description") or "",
                        "equip_nom": meta.get("equip_nom") or "",
                        "type_technique": meta.get("type_technique") or "",
                        "projet_nom": meta.get("projet_nom") or "",
                    })
    except Exception as ex:
        logger.exception(f"[planning_me] Erreur transformation CR : {ex}")

    items.sort(key=lambda x: (x.get("date") or "", x.get("heure_debut") or ""))
    return jsonify(items)

# ══ COMPTES RENDUS ══
@app.route("/api/comptes_rendus/<int:iid>")
@require_auth
def get_comptes_rendus(iid):
    db=get_db(); crs=rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
    for cr in crs:
        cr["releves"]=rows(db.execute("SELECT r.*,c.nom AS compteur_nom,c.numero,c.unite,c.localisation,ct.nom AS type_nom FROM releves_compteurs r JOIN compteurs c ON r.compteur_id=c.id LEFT JOIN compteur_types ct ON c.type_id=ct.id WHERE r.cr_id=? ORDER BY c.nom",(cr["id"],)))
    for cr in crs:
        try:
            cr["intervenants"]=rows(db.execute("""SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
                FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id WHERE ci.cr_id=?""",(cr["id"],)))
        except: cr["intervenants"]=[]
        try:
            cr["materiels"]=rows(db.execute("SELECT * FROM cr_materiels WHERE cr_id=? ORDER BY ordre,id",(cr["id"],)))
        except: cr["materiels"]=[]
    return jsonify(crs)

@app.route("/api/comptes_rendus/<int:iid>",methods=["POST"])
@require_auth
def create_compte_rendu(iid):
    d=request.json or {}; db=get_db()
    th = sum(float(iv.get("total_heures",0)) for iv in d.get("intervenants",[]))
    cr_num = next_numero(db,"CR","comptes_rendus","numero") if "numero" in [r[1] for r in db.execute("PRAGMA table_info(comptes_rendus)").fetchall()] else None
    if cr_num:
        db.execute("INSERT INTO comptes_rendus (intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,total_heures,numero) VALUES (?,?,?,?,?,?,?,?,?)",
                   (iid,d.get("date_intervention") or None,d.get("observations",""),d.get("actions_realisees",""),d.get("mesures",""),d.get("recommandations",""),d.get("conclusion",""),th,cr_num))
    else:
        db.execute("INSERT INTO comptes_rendus (intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,total_heures) VALUES (?,?,?,?,?,?,?,?)",
                   (iid,d.get("date_intervention") or None,d.get("observations",""),d.get("actions_realisees",""),d.get("mesures",""),d.get("recommandations",""),d.get("conclusion",""),th))
    db.commit(); cr_id=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    # Mettre à jour nb_deplacements si fourni (colonne ajoutée via migration)
    try:
        nbd = int(d.get("nb_deplacements") or 0)
        if nbd > 0:
            db.execute("UPDATE comptes_rendus SET nb_deplacements=? WHERE id=?", (nbd, cr_id))
            db.commit()
    except Exception: pass
    # Stocker intervenants dans cr_intervenants si table existe
    try:
        for iv in d.get("intervenants",[]):
            db.execute("INSERT INTO cr_intervenants (cr_id,utilisateur_id,nom,date,heure_debut,heure_fin,total_heures) VALUES (?,?,?,?,?,?,?)",
                       (cr_id,to_int(iv.get("utilisateur_id")),iv.get("nom",""),iv.get("date",""),iv.get("heure_debut",""),iv.get("heure_fin",""),iv.get("total_heures",0)))
        db.commit()
    except Exception: pass
    # Stocker matériels
    try:
        for idx, m in enumerate(d.get("materiels",[])):
            des = (m.get("designation","") or "").strip()
            if not des: continue
            qte = float(m.get("quantite") or 0)
            db.execute("INSERT INTO cr_materiels (cr_id,designation,quantite,ordre) VALUES (?,?,?,?)",
                       (cr_id, des, qte, idx))
        db.commit()
    except Exception: pass
    return jsonify({"id":cr_id}),201

@app.route("/api/comptes_rendus/cr/<int:cr_id>",methods=["PATCH"])
@require_role("admin","manager")
def update_compte_rendu(cr_id):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["date_intervention","observations","actions_realisees","mesures","recommandations","conclusion","total_heures","nb_deplacements"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if sets: params.append(cr_id); db.execute(f"UPDATE comptes_rendus SET {chr(44).join(sets)} WHERE id=?",params)
    if "intervenants" in d:
        db.execute("DELETE FROM cr_intervenants WHERE cr_id=?",(cr_id,))
        for iv in d["intervenants"]:
            db.execute("INSERT INTO cr_intervenants (cr_id,utilisateur_id,nom,date,heure_debut,heure_fin,total_heures) VALUES (?,?,?,?,?,?,?)",
                       (cr_id,to_int(iv.get("utilisateur_id")),iv.get("nom",""),iv.get("date",""),iv.get("heure_debut",""),iv.get("heure_fin",""),iv.get("total_heures",0)))
    if "materiels" in d:
        db.execute("DELETE FROM cr_materiels WHERE cr_id=?",(cr_id,))
        for idx, m in enumerate(d["materiels"]):
            des = (m.get("designation","") or "").strip()
            if not des: continue
            qte = float(m.get("quantite") or 0)
            db.execute("INSERT INTO cr_materiels (cr_id,designation,quantite,ordre) VALUES (?,?,?,?)",
                       (cr_id, des, qte, idx))
    db.commit(); return jsonify({"ok":True})

@app.route("/api/comptes_rendus/cr/<int:cr_id>",methods=["DELETE"])
@require_role("admin","manager")
def delete_compte_rendu(cr_id):
    db=get_db(); db.execute("DELETE FROM cr_intervenants WHERE cr_id=?",(cr_id,))
    db.execute("DELETE FROM comptes_rendus WHERE id=?",(cr_id,)); db.commit()
    return jsonify({"ok":True})

# ══ TECHNIQUES ══
@app.route("/api/techniques")
@require_auth
def get_techniques():
    return jsonify(rows(get_db().execute("SELECT * FROM techniques ORDER BY nom")))

@app.route("/api/techniques",methods=["POST"])
@require_role("admin","manager")
def create_technique():
    d=request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db=get_db()
    try:
        db.execute("INSERT INTO techniques (nom,description) VALUES (?,?)",(d["nom"],d.get("description","")))
        db.commit(); return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/techniques/<int:tid>",methods=["PATCH"])
@require_role("admin","manager")
def update_technique(tid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["nom","description"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(tid); db.execute(f"UPDATE techniques SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/techniques/<int:tid>",methods=["DELETE"])
@require_role("admin","manager")
def delete_technique(tid):
    db=get_db(); db.execute("DELETE FROM techniques WHERE id=?",(tid,)); db.commit()
    return jsonify({"ok":True})

# ══ GAMMES ══
@app.route("/api/gammes")
@require_auth
def get_gammes():
    db=get_db(); gammes=rows(db.execute("SELECT * FROM gammes ORDER BY nom"))
    for g in gammes:
        g["operations"]=rows(db.execute("SELECT * FROM gamme_operations WHERE gamme_id=? ORDER BY ordre",(g["id"],)))
    return jsonify(gammes)

@app.route("/api/gammes/<int:gid>")
@require_auth
def get_gamme(gid):
    db=get_db(); g=one(db.execute("SELECT * FROM gammes WHERE id=?",(gid,)))
    if not g: return jsonify({"error":"Non trouve"}),404
    g["operations"]=rows(db.execute("SELECT * FROM gamme_operations WHERE gamme_id=? ORDER BY ordre",(gid,)))
    return jsonify(g)

@app.route("/api/gammes",methods=["POST"])
@require_role("admin","manager")
def create_gamme():
    d=request.json or {}
    if not d.get("nom") or not d.get("periodicite"): return jsonify({"error":"nom et periodicite requis"}),400
    db=get_db(); db.execute("INSERT INTO gammes (nom,periodicite,temps) VALUES (?,?,?)",(d["nom"],d["periodicite"],d.get("temps","00h00")))
    db.commit(); gid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for i,op in enumerate(d.get("operations",[])):
        if op.get("description"): db.execute("INSERT INTO gamme_operations (gamme_id,ordre,description) VALUES (?,?,?)",(gid,i,op["description"]))
    db.commit(); return jsonify({"id":gid}),201

@app.route("/api/gammes/<int:gid>",methods=["PATCH"])
@require_role("admin","manager")
def update_gamme(gid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["nom","periodicite","temps"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if sets: params.append(gid); db.execute(f"UPDATE gammes SET {chr(44).join(sets)} WHERE id=?",params)
    if "operations" in d:
        db.execute("DELETE FROM gamme_operations WHERE gamme_id=?",(gid,))
        for i,op in enumerate(d["operations"]):
            if op.get("description"): db.execute("INSERT INTO gamme_operations (gamme_id,ordre,description) VALUES (?,?,?)",(gid,i,op["description"]))
    db.commit(); return jsonify({"ok":True})

@app.route("/api/gammes/<int:gid>",methods=["DELETE"])
@require_role("admin","manager")
def delete_gamme(gid):
    db=get_db(); db.execute("DELETE FROM gammes WHERE id=?",(gid,)); db.commit()
    return jsonify({"ok":True})

# ══ SMTP ══
@app.route("/api/smtp")
@require_role("admin")
def get_smtp():
    r=one(get_db().execute("SELECT * FROM smtp_config WHERE id=1"))
    if r: r.pop("password",None)
    return jsonify(r or {})

@app.route("/api/smtp",methods=["PATCH"])
@require_role("admin")
def update_smtp():
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["host","port","username","password","sender_email","sender_name","use_tls","enabled"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(1); db.execute(f"UPDATE smtp_config SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/smtp/test",methods=["POST"])
@require_role("admin")
def test_smtp():
    d=request.json or {}; to=d.get("to") or request.user.get("email")
    if not to: return jsonify({"error":"Destinataire requis"}),400
    try: send_mail(to,"[GMAO] Test SMTP","Test de configuration SMTP depuis SOCOM GMAO."); return jsonify({"ok":True})
    except Exception as e: return jsonify({"error":str(e)}),500

# ══ EXPORT/IMPORT EXCEL ══
@app.route("/api/export/excel")
@require_role("admin","manager")
def export_excel():
    try:
        import openpyxl; from openpyxl.styles import Font,PatternFill,Alignment
        db=get_db(); wb=openpyxl.Workbook()
        BF=PatternFill("solid",fgColor="244298"); WF=Font(bold=True,color="FFFFFF")
        def make_sheet(ws,headers,data_rows):
            ws.append(headers)
            for cell in ws[1]: cell.font=WF; cell.fill=BF; cell.alignment=Alignment(horizontal="center")
            for row in data_rows: ws.append([str(v) if v is not None else "" for v in row])
            for col in ws.columns: ws.column_dimensions[col[0].column_letter].width=max(len(str(c.value or "")) for c in col)+4

        # Clients
        ws=wb.active; ws.title="Clients"
        make_sheet(ws,["ID","Société","Nom","Prénom","Email","Téléphone","Notes"],
            [(r["id"],r["societe"],r["nom"],r["prenom"],r["email"],r["telephone"],r["notes"])
             for r in rows(db.execute("SELECT * FROM clients ORDER BY societe"))])

        # Projets
        ws2=wb.create_sheet("Projets")
        make_sheet(ws2,["ID","Numéro","Nom","Client","Manager","Date début","Date fin","Statut"],
            [(r["id"],r["numero_projet"],r["nom"],r.get("client_nom",""),r.get("manager_nom",""),r["date_debut"],r["date_fin"],r["statut"])
             for r in rows(db.execute("""SELECT p.*,c.societe AS client_nom,u.nom AS manager_nom
                FROM projets p LEFT JOIN clients c ON p.client_id=c.id
                LEFT JOIN utilisateurs u ON p.manager_id=u.id ORDER BY p.nom"""))])

        # Equipements
        ws3=wb.create_sheet("Equipements")
        make_sheet(ws3,["ID","Désignation","Type","Projet","Localisation","Marque","Modèle","Puissance","N° Série","I/O","Mise en service","Statut"],
            [(e["id"],e["designation"],e["type_technique"],e.get("projet_nom",""),e.get("localisation",""),e.get("marque",""),e.get("modele",""),e.get("puissance",""),e.get("numero_serie",""),e.get("in_out",""),e.get("date_mise_en_service",""),e["statut"])
             for e in rows(db.execute("""SELECT e.*,p.nom AS projet_nom FROM equipements e
                JOIN projets p ON e.projet_id=p.id ORDER BY p.nom,e.designation"""))])

        # Pièces
        ws4=wb.create_sheet("Pieces")
        make_sheet(ws4,["ID","Type","Equipement","Projet","Qté","Référence","N° Série","Date install.","Durée vie (ans)","Fin de vie","Statut","Commentaire"],
            [(p["id"],p["type_piece"],p.get("equip_nom",""),p.get("projet_nom",""),p.get("quantite",1),p.get("reference",""),p.get("numero_serie",""),p.get("date_installation",""),p.get("duree_vie_estimee",""),p.get("date_fin_de_vie",""),p["statut"],p.get("commentaire",""))
             for p in rows(db.execute("""SELECT p.*,e.designation AS equip_nom,pr.nom AS projet_nom
                FROM pieces p JOIN equipements e ON p.equipement_id=e.id
                JOIN projets pr ON e.projet_id=pr.id ORDER BY pr.nom,e.designation"""))])

        # Interventions
        ws5=wb.create_sheet("Interventions")
        make_sheet(ws5,["ID","Numéro","Type","Statut","Equipement","Projet","Client","Technicien","Equipe","Date prévue","Date réalisation","Description"],
            [(i["id"],i["numero"],i["type"],i["statut"],i.get("equip_nom",""),i.get("projet_nom",""),i.get("client_nom",""),i.get("technicien_nom",""),i.get("equipe_nom",""),i.get("date_prevue",""),i.get("date_realisation",""),i.get("description",""))
             for i in rows(db.execute("""SELECT i.*,e.designation AS equip_nom,p.nom AS projet_nom,
                c.societe AS client_nom,u.nom AS technicien_nom,eq.nom AS equipe_nom
                FROM interventions i JOIN equipements e ON i.equipement_id=e.id
                JOIN projets p ON e.projet_id=p.id LEFT JOIN clients c ON p.client_id=c.id
                LEFT JOIN utilisateurs u ON i.technicien_id=u.id
                LEFT JOIN equipes eq ON i.equipe_id=eq.id ORDER BY i.created_at DESC"""))])

        # Comptes rendus
        ws6=wb.create_sheet("Comptes rendus")
        make_sheet(ws6,["ID","N° BT","Equipement","Date intervention","Observations","Actions réalisées","Mesures","Recommandations","Conclusion","Total heures"],
            [(r["id"],r.get("numero",""),r.get("equip_nom",""),r.get("date_intervention",""),r.get("observations",""),r.get("actions_realisees",""),r.get("mesures",""),r.get("recommandations",""),r.get("conclusion",""),r.get("total_heures",0))
             for r in rows(db.execute("""SELECT cr.*,i.numero,e.designation AS equip_nom
                FROM comptes_rendus cr JOIN interventions i ON cr.intervention_id=i.id
                JOIN equipements e ON i.equipement_id=e.id ORDER BY cr.created_at DESC"""))])

        # Gammes
        ws7=wb.create_sheet("Gammes")
        make_sheet(ws7,["ID","Nom","Périodicité","Temps","Opérations"],
            [(g["id"],g["nom"],g["periodicite"],g["temps"],
              " | ".join([o["description"] for o in rows(db.execute("SELECT * FROM gamme_operations WHERE gamme_id=? ORDER BY ordre",(g["id"],)))]))
             for g in rows(db.execute("SELECT * FROM gammes ORDER BY nom"))])

        # Techniques
        ws8=wb.create_sheet("Techniques")
        make_sheet(ws8,["ID","Nom","Description"],
            [(t["id"],t["nom"],t.get("description",""))
             for t in rows(db.execute("SELECT * FROM techniques ORDER BY nom"))])

        # Utilisateurs
        ws9=wb.create_sheet("Utilisateurs")
        make_sheet(ws9,["ID","Nom","Email","Rôle","Actif"],
            [(u["id"],u["nom"],u["email"],u["role"],u["actif"])
             for u in rows(db.execute("SELECT * FROM utilisateurs ORDER BY nom"))])

        # Equipes
        ws10=wb.create_sheet("Equipes")
        make_sheet(ws10,["ID","Nom","Manager","Membres"],
            [(eq["id"],eq["nom"],eq.get("manager_nom",""),
              " | ".join([m["nom"] for m in rows(db.execute("""SELECT u.nom FROM utilisateurs u
                JOIN equipe_membres em ON em.technicien_id=u.id WHERE em.equipe_id=?""",(eq["id"],)))]))
             for eq in rows(db.execute("""SELECT e.*,u.nom AS manager_nom FROM equipes e
                LEFT JOIN utilisateurs u ON e.manager_id=u.id ORDER BY e.nom"""))])

        buf=io.BytesIO(); wb.save(buf); buf.seek(0)
        return send_file(buf,mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        as_attachment=True,download_name=f"gmao_export_{today()}.xlsx")
    except ImportError: return jsonify({"error":"openpyxl non installe"}),500
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/import/excel",methods=["POST"])
@require_role("admin")
def import_excel():
    try:
        import openpyxl; f=request.files.get("file")
        if not f: return jsonify({"error":"Fichier requis"}),400
        wb=openpyxl.load_workbook(f); db=get_db(); count=0
        if "Equipements" in wb.sheetnames:
            ws=wb["Equipements"]
            for row in ws.iter_rows(min_row=2,values_only=True):
                if not row[1]: continue
                try:
                    db.execute("INSERT OR IGNORE INTO equipements (designation,type_technique,localisation,marque,modele,statut,projet_id) VALUES (?,?,?,?,?,?,1)",
                               (row[1],row[2] or "UPS",row[4] or "",row[5] or "",row[6] or "",row[7] or "EN_SERVICE")); count+=1
                except Exception: pass
        db.commit(); return jsonify({"ok":True,"imported":count})
    except ImportError: return jsonify({"error":"openpyxl non installe"}),500
    except Exception as e: return jsonify({"error":str(e)}),500

# ══ PDF RAPPORT ══
@app.route("/api/interventions/<int:iid>/pdf")
@require_auth
def generate_pdf(iid):
    try: from rapport_pdf import generate_rapport
    except ImportError: return jsonify({"error":"Module rapport_pdf non disponible"}),500
    db=get_db()
    i=one(db.execute("""SELECT i.*,
           e.designation AS equip_nom, e.type_technique, e.localisation, e.marque, e.modele,
           e.puissance, e.numero_serie, e.in_out, e.date_mise_en_service AS eq_mise_service,
           e.statut AS eq_statut, e.notes AS eq_notes, e.technique_id AS eq_technique_id,
           p.nom AS projet_nom, p.numero_projet,
           c.societe AS client_nom,
           u.nom AS technicien_nom
           FROM interventions i
           JOIN equipements e ON i.equipement_id=e.id
           JOIN projets p ON e.projet_id=p.id
           LEFT JOIN clients c ON p.client_id=c.id
           LEFT JOIN utilisateurs u ON i.technicien_id=u.id
           WHERE i.id=?""",(iid,)))
    if not i: return jsonify({"error":"Non trouve"}),404
    crs=rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
    for cr in crs:
        cr["intervenants"]=rows(db.execute("""
            SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
            FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id
            WHERE ci.cr_id=? ORDER BY ci.id""",(cr["id"],)))
        try:
            cr["materiels"]=rows(db.execute("SELECT * FROM cr_materiels WHERE cr_id=? ORDER BY ordre,id",(cr["id"],)))
        except: cr["materiels"]=[]
    # Construire la liste structurée des comptes-rendus pour le PDF
    def _calc_heures(hd, hf):
        """Calcule la différence d'heures entre deux horaires HH:MM.
        Si heure_fin < heure_debut, considère un passage minuit (+24h).
        Renvoie un float (ex: 2.25 pour 2h15) ou 0 si format invalide.
        """
        try:
            if not hd or not hf: return 0.0
            hd_parts = str(hd).split(":"); hf_parts = str(hf).split(":")
            if len(hd_parts)<2 or len(hf_parts)<2: return 0.0
            m_debut = int(hd_parts[0])*60 + int(hd_parts[1])
            m_fin = int(hf_parts[0])*60 + int(hf_parts[1])
            diff = m_fin - m_debut
            # Passage minuit : ajouter 24h si fin < début
            if diff < 0:
                diff += 24 * 60
            return round(diff / 60.0, 4)
        except Exception:
            return 0.0
    comptes_rendus_pdf = []
    for cr in crs:
        ivs = []
        for iv in cr.get("intervenants", []):
            nom = iv.get("nom", "") or ""
            if not nom and iv.get("utilisateur_id"):
                u = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?", (iv["utilisateur_id"],)))
                if u: nom = u["nom"]
            # Total : priorité à la valeur stockée si >0, sinon calcul depuis horaires
            total_iv = 0.0
            try: total_iv = float(iv.get("total_heures", 0) or 0)
            except Exception: pass
            if total_iv <= 0:
                total_iv = _calc_heures(iv.get("heure_debut",""), iv.get("heure_fin",""))
            ivs.append({
                "nom": nom or "—",
                "date": iv.get("date", "") or cr.get("date_intervention", ""),
                "heure_debut": iv.get("heure_debut", ""),
                "heure_fin": iv.get("heure_fin", ""),
                "total_heures": total_iv
            })
        # Fallback : si pas d'intervenants CR, utiliser le technicien principal
        if not ivs and i.get("technicien_nom"):
            ivs.append({
                "nom": i["technicien_nom"],
                "date": cr.get("date_intervention", ""),
                "heure_debut": "",
                "heure_fin": "",
                "total_heures": cr.get("total_heures", 0)
            })
        comptes_rendus_pdf.append({
            "date": cr.get("date_intervention", "") or "—",
            "numero": cr.get("numero", "") or "",
            "observations": cr.get("observations", "") or "",
            "intervenants": ivs,
            "materiels": [
                {"designation": m.get("designation",""), "quantite": m.get("quantite",0)}
                for m in cr.get("materiels", []) if m.get("designation","")
            ],
        })
    # Liste globale des matériels (toutes les lignes, même en doublon)
    materiels_globaux = []
    for cr in comptes_rendus_pdf:
        for m in cr.get("materiels", []):
            materiels_globaux.append({
                "designation": m["designation"],
                "quantite": m["quantite"],
                "cr_numero": cr.get("numero","") or ""
            })
    # Déplacement : km vient du projet, nombre vient du/des CR(s) (dépannage uniquement)
    depl_km = 0.0; depl_nb = 0
    # Récupérer km depuis le projet (via l'équipement)
    if i.get("equipement_id"):
        try:
            proj = one(db.execute("""SELECT p.deplacement_km
                FROM projets p JOIN equipements e ON e.projet_id=p.id WHERE e.id=?""",
                (i["equipement_id"],)))
            if proj:
                depl_km = float(proj.get("deplacement_km") or 0)
        except Exception: pass
    # Somme des nb_deplacements de tous les CRs
    try:
        for cr in crs:
            depl_nb += int(cr.get("nb_deplacements") or 0)
    except Exception: pass
    # Date du bon : première date de CR, sinon date_realisation ou date_prevue
    if comptes_rendus_pdf:
        date_iv = comptes_rendus_pdf[0].get("date", "") or i.get("date_realisation") or i.get("date_prevue") or today()
    else:
        date_iv = i.get("date_realisation") or i.get("date_prevue") or today()
    date_iv = (date_iv or "").split("\n")[0][:10]
    # Équipement affiché
    eq = i.get("equip_nom", "—")
    marque_modele = ""
    if i.get("marque") or i.get("modele"):
        marque_modele = f"{i.get('marque','')} {i.get('modele','')}".strip()
    # Intervenants (synthèse : noms uniques)
    noms_uniques = []
    seen_n = set()
    for cr in comptes_rendus_pdf:
        for iv in cr.get("intervenants", []):
            n = iv.get("nom", "")
            if n and n != "—" and n not in seen_n:
                seen_n.add(n); noms_uniques.append(n)
    if not noms_uniques and i.get("technicien_nom"):
        noms_uniques = [i["technicien_nom"]]
    intervenants_str = ", ".join(noms_uniques) if noms_uniques else "—"
    # Technique (nom lisible)
    technique = i.get("type_technique", "") or "—"
    # Récupérer le nom complet de la technique depuis la table techniques si lié
    try:
        tech_row = one(db.execute("SELECT t.nom FROM techniques t JOIN equipements e ON e.technique_id=t.id WHERE e.id=?", (i["equipement_id"],)))
        if tech_row and tech_row.get("nom"):
            technique = tech_row["nom"]
    except Exception:
        pass
    try:
        pdf = generate_rapport({
            "type_label": i.get("type", ""),
            "numero_iv": i.get("numero", "—"),
            "date": date_iv,
            "client": i.get("client_nom", "—"),
            "numero_projet": i.get("numero_projet", "") or "—",
            "projet_nom": i.get("projet_nom", "") or "",
            "equipement": eq,
            "marque_modele": marque_modele or "—",
            "localisation": i.get("localisation", "") or "—",
            "technique": technique,
            # Infos complémentaires de la fiche équipement
            "eq_puissance": i.get("puissance", "") or "",
            "eq_numero_serie": i.get("numero_serie", "") or "",
            "eq_in_out": i.get("in_out", "") or "",
            "eq_date_mise_service": i.get("eq_mise_service", "") or "",
            "eq_statut": i.get("eq_statut", "") or "",
            "eq_notes": i.get("eq_notes", "") or "",
            "intervenants": intervenants_str,
            "description": i.get("description", "") or "",
            "comptes_rendus": comptes_rendus_pdf,
            "materiels_globaux": materiels_globaux,
            "deplacement_km": depl_km,
            "nb_deplacements": depl_nb,
        })
    except Exception as e:
        import traceback
        logger.error(f"[generate_pdf] erreur iid={iid}: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Erreur PDF : {str(e)}"}), 500
    fn = f"Rapport_{i.get('numero','BT00000')}_{(i.get('client_nom') or 'SOCOM').replace(' ','_')}.pdf"
    return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=fn)
# ══ MIGRATIONS PLANNINGS ══
def migrate_plannings(db):
    # Migration plannings table
    pcols = [r[1] for r in db.execute("PRAGMA table_info(plannings)").fetchall()]
    for col, typ, default in [
        ("equipe_id", "INTEGER", "NULL"),
        ("heure_debut", "TEXT", "'08:00'"),
    ]:
        if col not in pcols:
            try: db.execute(f"ALTER TABLE plannings ADD COLUMN {col} {typ} DEFAULT {default}")
            except Exception: pass
    # Migration equipements
    cols = [r[1] for r in db.execute("PRAGMA table_info(equipements)").fetchall()]
    for col, typ, default in [
        ("planning_id", "INTEGER", "NULL"),
        ("semaine_planif", "INTEGER", "NULL"),
        ("jour_semaine_planif", "INTEGER", "NULL"),
        ("intervention_samedi", "INTEGER", "0"),
        ("intervention_dimanche", "INTEGER", "0"),
    ]:
        if col not in cols:
            db.execute(f"ALTER TABLE equipements ADD COLUMN {col} {typ} DEFAULT {default}")
    db.commit()

# ══ PLANNINGS ══
@app.route("/api/plannings")
@require_auth
def get_plannings():
    return jsonify(rows(get_db().execute("SELECT * FROM plannings ORDER BY nom")))

@app.route("/api/plannings", methods=["POST"])
@require_role("admin","manager")
def create_planning():
    d = request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db = get_db()
    db.execute("INSERT INTO plannings (nom,equipe_id,heures_par_jour,heure_debut) VALUES (?,?,?,?)",
               (d["nom"],d.get("equipe_id"),d.get("heures_par_jour",8.0),d.get("heure_debut","08:00")))
    db.commit()
    return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/plannings/<int:pid>", methods=["PATCH"])
@require_role("admin","manager")
def update_planning(pid):
    d = request.json or {}; db = get_db(); sets,params=[],[]
    for f in ["nom","equipe_id","heures_par_jour","heure_debut"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(pid)
    db.execute(f"UPDATE plannings SET {chr(44).join(sets)} WHERE id=?",params)
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/plannings/<int:pid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_planning(pid):
    db = get_db()
    db.execute("UPDATE equipements SET planning_id=NULL WHERE planning_id=?",(pid,))
    db.execute("DELETE FROM plannings WHERE id=?",(pid,))
    db.commit()
    return jsonify({"ok":True})


