"""
SOCOM GMAO — Backend v3.0 — Version finale
"""
import hashlib, json, os, sqlite3, smtplib, io
from datetime import datetime, date, timedelta
from functools import wraps
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS

BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.environ.get("GMAO_DB", str(BASE_DIR / "gmao.db"))

app = Flask(__name__)
CORS(app, origins="*")

@app.teardown_appcontext
def close_db(error):
    pass  # SQLite connections are closed automatically

import threading
_db_lock = threading.Lock()

# ══════════════════════════════════════════════════════════
# DB HELPERS
# ══════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn

def rows(cur): return [dict(r) for r in cur.fetchall()]
def one(cur):  r = cur.fetchone(); return dict(r) if r else None
def hp(p):     return hashlib.sha256(p.encode()).hexdigest()
def now():     return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def today():   return date.today().isoformat()

def to_int(v):
    try: return int(v) if v not in (None, "", 0) else None
    except: return None

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'technicien' CHECK(role IN ('admin','manager','technicien')),
        actif INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        societe TEXT NOT NULL, nom TEXT, prenom TEXT,
        email TEXT, telephone TEXT, notes TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS projets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        numero_projet TEXT NOT NULL UNIQUE, nom TEXT NOT NULL,
        client_id INTEGER NOT NULL REFERENCES clients(id),
        manager_id INTEGER REFERENCES utilisateurs(id),
        description TEXT, date_debut TEXT, date_fin TEXT,
        statut TEXT NOT NULL DEFAULT 'EN_COURS' CHECK(statut IN ('EN_COURS','TERMINE','SUSPENDU')),
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS equipements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        projet_id INTEGER NOT NULL REFERENCES projets(id),
        designation TEXT NOT NULL,
        type_technique TEXT NOT NULL CHECK(type_technique IN (
            'UPS','STS','HAUTE_TENSION','GROUPE_ELECTROGENE',
            'ECLAIRAGE_SECOURS','DETECTION_INCENDIE','DESENFUMAGE')),
        localisation TEXT, marque TEXT, modele TEXT,
        puissance TEXT, numero_serie TEXT, in_out TEXT,
        date_mise_en_service TEXT,
        statut TEXT NOT NULL DEFAULT 'EN_SERVICE' CHECK(statut IN ('EN_SERVICE','HORS_SERVICE')),
        technique TEXT DEFAULT '',
        gamme_id INTEGER REFERENCES gammes(id),
        technique_id INTEGER REFERENCES techniques(id),
        notes TEXT, created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS pieces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        equipement_id INTEGER NOT NULL REFERENCES equipements(id) ON DELETE CASCADE,
        type_piece TEXT NOT NULL CHECK(type_piece IN (
            'BATTERIES','VENTILATEURS','CONDENSATEURS_AC','CONDENSATEURS_DC','CARTE_ALIMENTATION')),
        date_installation TEXT, duree_vie_estimee INTEGER,
        date_fin_de_vie TEXT,
        statut TEXT NOT NULL DEFAULT 'OK' CHECK(statut IN ('OK','A_SURVEILLER','A_REMPLACER')),
        quantite INTEGER DEFAULT 1,
        numero_serie TEXT DEFAULT '',
        reference TEXT DEFAULT '',
        commentaire TEXT, created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS equipes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        manager_id INTEGER REFERENCES utilisateurs(id),
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS equipe_membres (
        equipe_id INTEGER NOT NULL REFERENCES equipes(id) ON DELETE CASCADE,
        technicien_id INTEGER NOT NULL REFERENCES utilisateurs(id),
        PRIMARY KEY (equipe_id, technicien_id)
    );
    CREATE TABLE IF NOT EXISTS interventions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        numero TEXT NOT NULL UNIQUE,
        equipement_id INTEGER NOT NULL REFERENCES equipements(id),
        technicien_id INTEGER REFERENCES utilisateurs(id),
        equipe_id INTEGER REFERENCES equipes(id),
        type TEXT NOT NULL CHECK(type IN ('MAINTENANCE','DEPANNAGE')),
        statut TEXT NOT NULL DEFAULT 'A_PLANIFIER'
            CHECK(statut IN ('A_PLANIFIER','PLANIFIEE','EN_COURS','TERMINEE','ANNULEE')),
        date_creation TEXT DEFAULT (datetime('now')),
        date_prevue TEXT, date_realisation TEXT,
        description TEXT, rapport TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS comptes_rendus (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        intervention_id INTEGER NOT NULL REFERENCES interventions(id) ON DELETE CASCADE,
        date_intervention TEXT,
        observations TEXT, actions_realisees TEXT,
        mesures TEXT, recommandations TEXT, conclusion TEXT,
        total_heures REAL DEFAULT 0, photos TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS cr_intervenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cr_id INTEGER NOT NULL REFERENCES comptes_rendus(id) ON DELETE CASCADE,
        utilisateur_id INTEGER REFERENCES utilisateurs(id),
        nom TEXT DEFAULT '',
        date TEXT, heure_debut TEXT, heure_fin TEXT,
        total_heures REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS techniques (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '',
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS gammes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        periodicite TEXT NOT NULL,
        temps TEXT DEFAULT '00h00',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS gamme_operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gamme_id INTEGER NOT NULL REFERENCES gammes(id) ON DELETE CASCADE,
        ordre INTEGER DEFAULT 0,
        description TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS smtp_config (
        id INTEGER PRIMARY KEY CHECK(id=1),
        host TEXT DEFAULT '', port INTEGER DEFAULT 587,
        username TEXT DEFAULT '', password TEXT DEFAULT '',
        use_tls INTEGER DEFAULT 1,
        sender_email TEXT DEFAULT '', sender_name TEXT DEFAULT 'SOCOM GMAO',
        enabled INTEGER DEFAULT 0
    );
    INSERT OR IGNORE INTO smtp_config (id) VALUES (1);
    """)
    db.commit()
    pw = hp("admin")
    try:
        db.execute("INSERT OR IGNORE INTO utilisateurs (nom,email,password,role) VALUES (?,?,?,?)",
                   ("Administrateur","admin@gmao.fr",pw,"admin"))
        db.commit()
    except: pass
    db.close()

def criticite(eid, db):
    ss = [r["statut"] for r in db.execute("SELECT statut FROM pieces WHERE equipement_id=?", (eid,)).fetchall()]
    if "A_REMPLACER"  in ss: return "CRITIQUE"
    if "A_SURVEILLER" in ss: return "ATTENTION"
    return "OK"

def fdv(di, ans):
    try:
        return (datetime.strptime(di,"%Y-%m-%d") + timedelta(days=int(ans)*365)).strftime("%Y-%m-%d")
    except: return None

def statut_piece(fdv_):
    if not fdv_: return "OK"
    try:
        d = (datetime.strptime(fdv_,"%Y-%m-%d").date() - date.today()).days
        return "A_REMPLACER" if d < 0 else "A_SURVEILLER" if d < 180 else "OK"
    except: return "OK"

def gen_num(db, prefix, table):
    n = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] + 1
    return f"{prefix}{n:05d}"

# ══════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════
def check_auth():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return None
    t = auth[7:]
    if ":" not in t: return None
    uid, pw = t.split(":",1)
    try:
        db = get_db()
        return one(db.execute(
            "SELECT id,nom,email,role FROM utilisateurs WHERE id=? AND password=? AND actif=1",
            (uid, pw)))
    except: return None

def require_auth(fn):
    @wraps(fn)
    def w(*a,**k):
        u = check_auth()
        if not u: return jsonify({"error":"Non autorisé"}),401
        request.user = u; return fn(*a,**k)
    return w

def require_role(*roles):
    def dec(fn):
        @wraps(fn)
        def w(*a,**k):
            u = check_auth()
            if not u: return jsonify({"error":"Non autorisé"}),401
            if u["role"] not in roles: return jsonify({"error":"Accès interdit"}),403
            request.user = u; return fn(*a,**k)
        return w
    return dec

# ══════════════════════════════════════════════════════════
# MAIL
# ══════════════════════════════════════════════════════════
def send_mail(to, subj, body, attachments=None):
    try:
        db  = get_db()
        cfg = one(db.execute("SELECT * FROM smtp_config WHERE id=1"))
        if not cfg or not cfg["enabled"]: return
        msg = MIMEMultipart()
        msg["From"]    = f"{cfg['sender_name']} <{cfg['sender_email']}>"
        msg["To"]      = to; msg["Subject"] = subj
        msg.attach(MIMEText(body,"plain","utf-8"))
        if attachments:
            from email.mime.base import MIMEBase
            from email import encoders
            for fname, fdata in attachments:
                part = MIMEBase('application','octet-stream')
                part.set_payload(fdata)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{fname}"')
                msg.attach(part)
        with smtplib.SMTP(cfg["host"],cfg["port"],timeout=10) as s:
            if cfg["use_tls"]: s.starttls()
            if cfg["username"]: s.login(cfg["username"],cfg["password"])
            s.sendmail(cfg["sender_email"],to,msg.as_string())
    except Exception as e: print(f"[MAIL] {e}")

def notify(iid, action):
    try:
        db = get_db()
        r  = one(db.execute(
            """SELECT i.numero,i.type,i.statut,e.designation,p.nom AS projet,
               u.email AS mgr_email,u.nom AS mgr_nom,
               i.date_realisation,i.technicien_id
               FROM interventions i
               JOIN equipements e ON i.equipement_id=e.id
               JOIN projets p ON e.projet_id=p.id
               LEFT JOIN utilisateurs u ON p.manager_id=u.id
               WHERE i.id=?""",(iid,)))
        if not r or not r["mgr_email"]: return
        attachments = []
        if r["statut"] == "TERMINEE":
            try:
                from rapport_pdf import generate_rapport
                crs = rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
                for cr in crs:
                    cr["intervenants"] = rows(db.execute(
                        """SELECT ci.*,COALESCE(u2.nom,ci.nom,'') AS nom
                           FROM cr_intervenants ci LEFT JOIN utilisateurs u2 ON ci.utilisateur_id=u2.id
                           WHERE ci.cr_id=?""",(cr["id"],)))
                def mf(field):
                    return '\n'.join([cr.get(field,'') for cr in crs if cr.get(field,'')])
                all_ivs,seen = [],set()
                for cr in crs:
                    for iv in cr.get('intervenants',[]):
                        k = (iv.get('nom',''),iv.get('date',''))
                        if k not in seen: seen.add(k); all_ivs.append(iv)
                date_iv = mf('date_intervention') or (r.get('date_realisation','') or today())
                date_iv = date_iv.split('\n')[0][:10]
                titre_rapport = "RAPPORT D'INTERVENTION - DEPANNAGE" if r["type"]=="DEPANNAGE" else "RAPPORT D'INTERVENTION"
                pdf_bytes = generate_rapport({
                    'titre_rapport': titre_rapport, 'titre': r["designation"],
                    'client': r["projet"], 'numero_projet': "--",
                    'numero_iv': r["numero"], 'type_label': r["type"],
                    'date': date_iv, 'equipement': r["designation"],
                    'localisation': "--", 'intervenants': "--",
                    'intervenants_list': all_ivs,
                    'observations': mf('observations'),
                    'actions_realisees': mf('actions_realisees'),
                    'mesures': mf('mesures'),
                    'recommandations': mf('recommandations'),
                    'conclusion': mf('conclusion'),
                })
                attachments.append((f"rapport_{r['numero']}.pdf", pdf_bytes))
            except Exception as pe:
                print(f"[PDF] {pe}")
        send_mail(r["mgr_email"],
            f"[GMAO] {action} - {r['numero']}",
            f"Bonjour {r['mgr_nom']},\n\n{action}\n\nRef: {r['numero']}\nType: {r['type']}\nStatut: {r['statut']}\nEquipement: {r['designation']}\nProjet: {r['projet']}\n\nCordialement,\nSOCOM GMAO",
            attachments=attachments or None)
    except Exception as e: print(f"[NOTIFY] {e}")


