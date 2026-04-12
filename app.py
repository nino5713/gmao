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
def send_mail(to, subj, body):
    try:
        db  = get_db()
        cfg = one(db.execute("SELECT * FROM smtp_config WHERE id=1"))
        if not cfg or not cfg["enabled"]: return
        msg = MIMEMultipart()
        msg["From"]    = f"{cfg['sender_name']} <{cfg['sender_email']}>"
        msg["To"]      = to; msg["Subject"] = subj
        msg.attach(MIMEText(body,"plain","utf-8"))
        with smtplib.SMTP(cfg["host"],cfg["port"],timeout=10) as s:
            if cfg["use_tls"]: s.starttls()
            if cfg["username"]: s.login(cfg["username"],cfg["password"])
            s.sendmail(cfg["sender_email"],to,msg.as_string())
    except Exception as e: print(f"[MAIL] {e}")

def notify(iid, action):
    try:
        db = get_db()
        r  = one(db.execute("""
            SELECT i.numero,i.type,i.statut,e.designation,p.nom AS projet,
                   u.email AS mgr_email,u.nom AS mgr_nom
            FROM interventions i
            JOIN equipements e ON i.equipement_id=e.id
            JOIN projets p ON e.projet_id=p.id
            LEFT JOIN utilisateurs u ON p.manager_id=u.id
            WHERE i.id=?""",(iid,)))
        if r and r["mgr_email"]:
            send_mail(r["mgr_email"],f"[GMAO] {action} — {r['numero']}",
                f"Bonjour {r['mgr_nom']},\n\n{action}\n\nRef: {r['numero']}\nType: {r['type']}\nStatut: {r['statut']}\nEquipement: {r['designation']}\nProjet: {r['projet']}\n\nCordialement,\nSOCOM GMAO")
    except Exception as e: print(f"[NOTIFY] {e}")

# ══════════════════════════════════════════════════════════
# FRONTEND
# ══════════════════════════════════════════════════════════
@app.route("/")
def index():
    f = BASE_DIR/"index.html"
    return send_file(str(f)) if f.exists() else ("index.html introuvable",404)

@app.route("/mobile")
def mobile():
    f = BASE_DIR/"gmao_mobile.html"
    return send_file(str(f)) if f.exists() else ("gmao_mobile.html introuvable",404)

@app.route("/sw.js")
def sw():
    f = BASE_DIR/"sw.js"
    return Response(f.read_text(), mimetype="application/javascript",
                    headers={"Service-Worker-Allowed":"/"}) if f.exists() else ("",404)

@app.route("/manifest.json")
def manifest():
    return jsonify({"name":"GMAO Terrain","short_name":"GMAO","start_url":"/mobile",
                    "display":"standalone","background_color":"#1e293b","theme_color":"#3b82f6",
                    "icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png"}]})

@app.route("/health")
def health():
    try: get_db().execute("SELECT 1"); return jsonify({"status":"ok","time":now()})
    except Exception as e: return jsonify({"status":"error","error":str(e)}),500

# ══════════════════════════════════════════════════════════
# AUTH API
# ══════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    em = (d.get("email") or "").strip()
    pw = (d.get("password") or "").strip()
    if not em or not pw: return jsonify({"error":"Identifiants manquants"}),400
    try:
        db = get_db()
        r  = one(db.execute(
            "SELECT id,nom,email,role FROM utilisateurs WHERE email=? AND password=? AND actif=1",
            (em, hp(pw))))
        if not r: return jsonify({"error":"Identifiants incorrects"}),401
        r["token"] = f"{r['id']}:{hp(pw)}"
        return jsonify(r)
    except Exception as e: return jsonify({"error":str(e)}),500

# ══════════════════════════════════════════════════════════
# UTILISATEURS
# ══════════════════════════════════════════════════════════
@app.route("/api/utilisateurs")
@require_auth
def get_utilisateurs():
    return jsonify(rows(get_db().execute("SELECT id,nom,email,role,actif FROM utilisateurs ORDER BY nom")))

@app.route("/api/utilisateurs", methods=["POST"])
@require_role("admin")
def create_utilisateur():
    d = request.json or {}
    if not all([d.get("nom"),d.get("email"),d.get("password")]):
        return jsonify({"error":"nom, email, password requis"}),400
    db = get_db()
    try:
        db.execute("INSERT INTO utilisateurs (nom,email,password,role) VALUES (?,?,?,?)",
                   (d["nom"],d["email"],hp(d["password"]),d.get("role","technicien")))
        db.commit()
        return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/utilisateurs/<int:uid>", methods=["DELETE"])
@require_role("admin")
def delete_utilisateur(uid):
    db = get_db()
    # Ne pas supprimer son propre compte
    user = check_auth()
    if user and user["id"] == uid:
        return jsonify({"error":"Impossible de supprimer votre propre compte"}),400
    db.execute("DELETE FROM utilisateurs WHERE id=?",(uid,))
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/utilisateurs/<int:uid>", methods=["PATCH"])
@require_role("admin")
def update_utilisateur(uid):
    d = request.json or {}
    db = get_db()
    sets,params=[],[]
    for f in ["nom","email","role","actif"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if d.get("password"): sets.append("password=?"); params.append(hp(d["password"]))
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(uid)
    db.execute(f"UPDATE utilisateurs SET {','.join(sets)} WHERE id=?",params)
    db.commit(); return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# CLIENTS
# ══════════════════════════════════════════════════════════
@app.route("/api/clients")
@require_auth
def get_clients():
    return jsonify(rows(get_db().execute("SELECT * FROM clients ORDER BY societe")))

@app.route("/api/clients", methods=["POST"])
@require_auth
def create_client():
    d = request.json or {}
    if not d.get("societe"): return jsonify({"error":"societe requis"}),400
    db = get_db()
    db.execute("INSERT INTO clients (societe,nom,prenom,email,telephone,notes) VALUES (?,?,?,?,?,?)",
               (d["societe"],d.get("nom",""),d.get("prenom",""),d.get("email",""),d.get("telephone",""),d.get("notes","")))
    db.commit()
    return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/clients/<int:cid>", methods=["PATCH"])
@require_auth
def update_client(cid):
    d = request.json or {}
    db = get_db()
    sets,params=[],[]
    for f in ["societe","nom","prenom","email","telephone","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(cid)
    db.execute(f"UPDATE clients SET {','.join(sets)} WHERE id=?",params)
    db.commit(); return jsonify({"ok":True})

@app.route("/api/clients/<int:cid>", methods=["DELETE"])
@require_role("admin")
def delete_client(cid):
    db = get_db()
    db.execute("DELETE FROM clients WHERE id=?",(cid,))
    db.commit(); return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# PROJETS
# ══════════════════════════════════════════════════════════
@app.route("/api/projets")
@require_auth
def get_projets():
    db   = get_db()
    user = request.user
    sql  = """SELECT p.*,c.societe AS client_nom,u.nom AS manager_nom
              FROM projets p LEFT JOIN clients c ON p.client_id=c.id
              LEFT JOIN utilisateurs u ON p.manager_id=u.id WHERE 1=1"""
    params = []
    if user["role"] == "manager":
        sql += " AND p.manager_id=?"; params.append(user["id"])
    elif user["role"] == "technicien":
        sql += """ AND p.id IN (SELECT DISTINCT e.projet_id FROM interventions i
                   JOIN equipements e ON i.equipement_id=e.id WHERE i.technicien_id=?)"""
        params.append(user["id"])
    return jsonify(rows(db.execute(sql+" ORDER BY p.nom", params)))

@app.route("/api/projets/<int:pid>")
@require_auth
def get_projet(pid):
    db = get_db()
    p  = one(db.execute("""SELECT p.*,c.societe AS client_nom,u.nom AS manager_nom
              FROM projets p LEFT JOIN clients c ON p.client_id=c.id
              LEFT JOIN utilisateurs u ON p.manager_id=u.id WHERE p.id=?""",(pid,)))
    if not p: return jsonify({"error":"Non trouvé"}),404
    p["equipements"] = rows(db.execute("SELECT id,designation,type_technique,statut FROM equipements WHERE projet_id=?",(pid,)))
    for e in p["equipements"]: e["criticite"] = criticite(e["id"],db)
    return jsonify(p)

@app.route("/api/projets", methods=["POST"])
@require_role("admin","manager")
def create_projet():
    d = request.json or {}
    if not d.get("nom") or not d.get("client_id"):
        return jsonify({"error":"nom et client_id requis"}),400
    db  = get_db()
    num = d.get("numero_projet") or gen_num(db,"PRJ","projets")
    try:
        db.execute("INSERT INTO projets (numero_projet,nom,client_id,manager_id,description,date_debut,date_fin,statut) VALUES (?,?,?,?,?,?,?,?)",
                   (num,d["nom"],d["client_id"],d.get("manager_id") or None,d.get("description",""),
                    d.get("date_debut") or None,d.get("date_fin") or None,d.get("statut","EN_COURS")))
        db.commit()
        return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0],"numero":num}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/projets/<int:pid>", methods=["PATCH"])
@require_role("admin","manager")
def update_projet(pid):
    d = request.json or {}
    db = get_db()
    sets,params=[],[]
    for f in ["nom","client_id","manager_id","description","date_debut","date_fin","statut","numero_projet"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f] or None)
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(pid)
    db.execute(f"UPDATE projets SET {','.join(sets)} WHERE id=?",params)
    db.commit(); return jsonify({"ok":True})

@app.route("/api/projets/<int:pid>", methods=["DELETE"])
@require_role("admin")
def delete_projet(pid):
    db = get_db()
    db.execute("DELETE FROM projets WHERE id=?",(pid,))
    db.commit(); return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# EQUIPEMENTS
# ══════════════════════════════════════════════════════════
@app.route("/api/equipements")
@require_auth
def get_equipements():
    db   = get_db()
    user = request.user
    sql  = """SELECT e.*,p.nom AS projet_nom,p.numero_projet
              FROM equipements e JOIN projets p ON e.projet_id=p.id WHERE 1=1"""
    params = []
    if request.args.get("projet_id"):
        sql += " AND e.projet_id=?"; params.append(request.args["projet_id"])
    if user["role"] == "manager":
        sql += " AND p.manager_id=?"; params.append(user["id"])
    # technicien voit tous les équipements (pas de filtre)
    equips = rows(db.execute(sql+" ORDER BY p.nom,e.designation",params))
    for e in equips:
        e["criticite"] = criticite(e["id"],db)
        e["nb_maintenance"] = db.execute(
            "SELECT COUNT(*) FROM interventions WHERE equipement_id=? AND type='MAINTENANCE'",(e["id"],)).fetchone()[0]
        e["nb_depannage"] = db.execute(
            "SELECT COUNT(*) FROM interventions WHERE equipement_id=? AND type='DEPANNAGE'",(e["id"],)).fetchone()[0]
    return jsonify(equips)

@app.route("/api/equipements/<int:eid>")
@require_auth
def get_equipement(eid):
    db = get_db()
    e  = one(db.execute("SELECT e.*,p.nom AS projet_nom,p.numero_projet FROM equipements e JOIN projets p ON e.projet_id=p.id WHERE e.id=?",(eid,)))
    if not e: return jsonify({"error":"Non trouvé"}),404
    pieces_raw = rows(db.execute("SELECT * FROM pieces WHERE equipement_id=? ORDER BY type_piece",(eid,)))
    for p in pieces_raw:
        nouveau_statut = statut_piece(p.get("date_fin_de_vie"))
        if nouveau_statut != p.get("statut") and p.get("date_fin_de_vie"):
            db.execute("UPDATE pieces SET statut=? WHERE id=?", (nouveau_statut, p["id"]))
            p["statut"] = nouveau_statut
    db.commit()
    e["pieces"]    = pieces_raw
    e["criticite"] = criticite(eid,db)
    return jsonify(e)

@app.route("/api/equipements", methods=["POST"])
@require_role("admin","manager")
def create_equipement():
    d = request.json or {}
    if not all([d.get("designation"),d.get("projet_id"),d.get("type_technique")]):
        return jsonify({"error":"designation, projet_id, type_technique requis"}),400
    db = get_db()
    db.execute("INSERT INTO equipements (projet_id,designation,type_technique,localisation,marque,modele,puissance,numero_serie,in_out,date_mise_en_service,statut,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (d["projet_id"],d["designation"],d["type_technique"],d.get("localisation",""),d.get("marque",""),
                d.get("modele",""),d.get("puissance",""),d.get("numero_serie",""),d.get("in_out",""),
                d.get("date_mise_en_service") or None,d.get("statut","EN_SERVICE"),d.get("notes","")))
    db.commit()
    return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/equipements/<int:eid>", methods=["PATCH"])
@require_role("admin","manager")
def update_equipement(eid):
    d = request.json or {}
    db = get_db()
    sets,params=[],[]
    for f in ["designation","type_technique","localisation","marque","modele","puissance","numero_serie","in_out","date_mise_en_service","statut","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(eid)
    db.execute(f"UPDATE equipements SET {','.join(sets)} WHERE id=?",params)
    db.commit(); return jsonify({"ok":True})

@app.route("/api/equipements/<int:eid>", methods=["DELETE"])
@require_role("admin")
def delete_equipement(eid):
    db = get_db()
    ivs = [r[0] for r in db.execute("SELECT id FROM interventions WHERE equipement_id=?",(eid,)).fetchall()]
    for iv_id in ivs:
        crs = [r[0] for r in db.execute("SELECT id FROM comptes_rendus WHERE intervention_id=?",(iv_id,)).fetchall()]
        for cr_id in crs:
            db.execute("DELETE FROM cr_intervenants WHERE cr_id=?",(cr_id,))
        db.execute("DELETE FROM comptes_rendus WHERE intervention_id=?",(iv_id,))
    db.execute("DELETE FROM interventions WHERE equipement_id=?",(eid,))
    db.execute("DELETE FROM pieces WHERE equipement_id=?",(eid,))
    db.execute("DELETE FROM equipements WHERE id=?",(eid,))
    db.commit()
    return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# PIECES
# ══════════════════════════════════════════════════════════
@app.route("/api/pieces")
@require_auth
def get_pieces():
    db  = get_db()
    sql = """SELECT p.*,e.designation AS equip_nom,pj.nom AS projet_nom
             FROM pieces p JOIN equipements e ON p.equipement_id=e.id
             JOIN projets pj ON e.projet_id=pj.id WHERE 1=1"""
    params = []
    if request.args.get("equipement_id"):
        sql += " AND p.equipement_id=?"; params.append(request.args["equipement_id"])
    if request.args.get("alertes"):
        sql += " AND p.statut IN ('A_SURVEILLER','A_REMPLACER')"
    pieces = rows(db.execute(sql+" ORDER BY p.date_fin_de_vie",params))
    # Mettre à jour automatiquement le statut selon la date de fin de vie
    for p in pieces:
        nouveau_statut = statut_piece(p.get("date_fin_de_vie"))
        if nouveau_statut != p.get("statut") and p.get("date_fin_de_vie"):
            db.execute("UPDATE pieces SET statut=? WHERE id=?", (nouveau_statut, p["id"]))
            p["statut"] = nouveau_statut
    db.commit()
    return jsonify(pieces)

@app.route("/api/pieces", methods=["POST"])
@require_role("admin","manager")
def create_piece():
    d = request.json or {}
    if not d.get("equipement_id") or not d.get("type_piece"):
        return jsonify({"error":"equipement_id et type_piece requis"}),400
    dv = fdv(d["date_installation"],d["duree_vie_estimee"]) if d.get("date_installation") and d.get("duree_vie_estimee") else None
    st = d.get("statut") or statut_piece(dv)
    db = get_db()
    db.execute("INSERT INTO pieces (equipement_id,type_piece,date_installation,duree_vie_estimee,date_fin_de_vie,statut,quantite,numero_serie,reference,commentaire) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (d["equipement_id"],d["type_piece"],d.get("date_installation") or None,d.get("duree_vie_estimee") or None,dv,st,d.get("quantite",1),d.get("numero_serie",""),d.get("reference",""),d.get("commentaire","")))
    db.commit()
    return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/pieces/<int:pid>", methods=["PATCH"])
@require_role("admin","manager")
def update_piece(pid):
    d  = request.json or {}
    db = get_db()
    p  = one(db.execute("SELECT * FROM pieces WHERE id=?",(pid,)))
    di = d.get("date_installation", p["date_installation"] if p else None)
    du = d.get("duree_vie_estimee", p["duree_vie_estimee"] if p else None)
    if di and du:
        d["date_fin_de_vie"] = fdv(di,int(du))
        if "statut" not in d: d["statut"] = statut_piece(d["date_fin_de_vie"])
    sets,params=[],[]
    for f in ["type_piece","date_installation","duree_vie_estimee","date_fin_de_vie","statut","quantite","numero_serie","reference","commentaire"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(pid)
    db.execute(f"UPDATE pieces SET {','.join(sets)} WHERE id=?",params)
    db.commit(); return jsonify({"ok":True})

@app.route("/api/pieces/<int:pid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_piece(pid):
    db = get_db()
    db.execute("DELETE FROM pieces WHERE id=?",(pid,))
    db.commit(); return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# EQUIPES
# ══════════════════════════════════════════════════════════
@app.route("/api/equipes")
@require_auth
def get_equipes():
    db = get_db()
    eq = rows(db.execute("SELECT e.*,u.nom AS manager_nom FROM equipes e LEFT JOIN utilisateurs u ON e.manager_id=u.id ORDER BY e.nom"))
    for e in eq:
        e["membres"] = rows(db.execute("SELECT u.id,u.nom,u.role FROM equipe_membres em JOIN utilisateurs u ON em.technicien_id=u.id WHERE em.equipe_id=?",(e["id"],)))
    return jsonify(eq)

@app.route("/api/equipes", methods=["POST"])
@require_role("admin","manager")
def create_equipe():
    d = request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db = get_db()
    db.execute("INSERT INTO equipes (nom,manager_id) VALUES (?,?)",(d["nom"],d.get("manager_id") or None))
    db.commit()
    eid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for mid in d.get("membres",[]):
        try: db.execute("INSERT OR IGNORE INTO equipe_membres VALUES (?,?)",(eid,mid))
        except: pass
    db.commit(); return jsonify({"id":eid}),201

@app.route("/api/equipes/<int:eid>", methods=["PATCH"])
@require_role("admin","manager")
def update_equipe(eid):
    d = request.json or {}
    db = get_db()
    sets,params=[],[]
    if "nom" in d: sets.append("nom=?"); params.append(d["nom"])
    if "manager_id" in d: sets.append("manager_id=?"); params.append(d["manager_id"] or None)
    if sets: params.append(eid); db.execute(f"UPDATE equipes SET {','.join(sets)} WHERE id=?",params)
    if "membres" in d:
        db.execute("DELETE FROM equipe_membres WHERE equipe_id=?",(eid,))
        for mid in d["membres"]:
            try: db.execute("INSERT OR IGNORE INTO equipe_membres VALUES (?,?)",(eid,mid))
            except: pass
    db.commit(); return jsonify({"ok":True})

@app.route("/api/equipes/<int:eid>", methods=["DELETE"])
@require_role("admin")
def delete_equipe(eid):
    db = get_db()
    db.execute("DELETE FROM equipes WHERE id=?",(eid,))
    db.commit(); return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# INTERVENTIONS
# ══════════════════════════════════════════════════════════
@app.route("/api/interventions")
@require_auth
def get_interventions():
    db   = get_db()
    user = request.user
    sql  = """SELECT i.*,e.designation AS equip_nom,e.type_technique,e.localisation,e.projet_id,
                     p.nom AS projet_nom,p.numero_projet,u.nom AS technicien_nom,eq.nom AS equipe_nom
              FROM interventions i
              JOIN equipements e ON i.equipement_id=e.id
              JOIN projets p ON e.projet_id=p.id
              LEFT JOIN utilisateurs u ON i.technicien_id=u.id
              LEFT JOIN equipes eq ON i.equipe_id=eq.id WHERE 1=1"""
    params = []
    if user["role"] == "technicien":
        eq_ids = [r[0] for r in db.execute(
            "SELECT equipe_id FROM equipe_membres WHERE technicien_id=?", (user["id"],)).fetchall()]
        if eq_ids:
            ph = ",".join(["?"]*len(eq_ids))
            sql += " AND (i.technicien_id=? OR i.equipe_id IN ("+ph+"))"
            params.append(user["id"])
            params.extend(eq_ids)
        else:
            sql += " AND i.technicien_id=?"; params.append(user["id"])
    elif user["role"] == "manager":
        sql += " AND p.manager_id=?"; params.append(user["id"])
    for arg,col in [("statut","i.statut"),("type","i.type"),("projet_id","e.projet_id"),("equipement_id","i.equipement_id")]:
        if request.args.get(arg): sql += f" AND {col}=?"; params.append(request.args[arg])
    if request.args.get("today"): sql += " AND DATE(i.date_prevue)=?"; params.append(today())
    return jsonify(rows(db.execute(sql+" ORDER BY i.date_creation DESC LIMIT 500",params)))

@app.route("/api/interventions/<int:iid>")
@require_auth
def get_intervention(iid):
    db = get_db()
    i  = one(db.execute("""SELECT i.*,e.designation AS equip_nom,e.type_technique,e.localisation,e.projet_id,
                                  p.nom AS projet_nom,p.numero_projet,u.nom AS technicien_nom,eq.nom AS equipe_nom
                           FROM interventions i
                           JOIN equipements e ON i.equipement_id=e.id
                           JOIN projets p ON e.projet_id=p.id
                           LEFT JOIN utilisateurs u ON i.technicien_id=u.id
                           LEFT JOIN equipes eq ON i.equipe_id=eq.id
                           WHERE i.id=?""",(iid,)))
    if not i: return jsonify({"error":"Non trouvé"}),404
    crs = rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at DESC",(iid,)))
    for cr in crs:
        cr["intervenants"] = rows(db.execute("""
            SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
            FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id
            WHERE ci.cr_id=?""",(cr["id"],)))
    i["comptes_rendus"] = crs
    return jsonify(i)

@app.route("/api/interventions", methods=["POST"])
@require_auth
def create_intervention():
    user = request.user
    d    = request.json or {}
    if not d.get("equipement_id") or not d.get("type"):
        return jsonify({"error":"equipement_id et type requis"}),400
    db   = get_db()
    num  = gen_num(db,"INT","interventions")
    tech = to_int(d.get("technicien_id")) or (user["id"] if user["role"]=="technicien" else None)
    eq_id = to_int(d.get("equipe_id"))
    db.execute("INSERT INTO interventions (numero,equipement_id,technicien_id,equipe_id,type,statut,date_prevue,description) VALUES (?,?,?,?,?,?,?,?)",
               (num,d["equipement_id"],tech,eq_id,d["type"],d.get("statut","A_PLANIFIER"),d.get("date_prevue") or None,d.get("description","")))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    try: notify(new_id,"Nouvelle intervention créée")
    except: pass
    return jsonify({"id":new_id,"numero":num}),201

@app.route("/api/interventions/<int:iid>", methods=["PATCH"])
@require_auth
def update_intervention(iid):
    d  = request.json or {}
    db = get_db()
    old = one(db.execute("SELECT statut FROM interventions WHERE id=?",(iid,)))
    sets,params=[],[]
    for f in ["technicien_id","equipe_id","type","statut","date_prevue","date_realisation","description","rapport"]:
        if f in d:
            v = to_int(d[f]) if f in ["technicien_id","equipe_id"] else d[f]
            sets.append(f"{f}=?"); params.append(v)
    if "statut" in d and d["statut"]=="TERMINEE" and "date_realisation" not in d:
        sets.append("date_realisation=?"); params.append(today())
    sets.append("updated_at=?"); params.append(now())
    params.append(iid)
    db.execute(f"UPDATE interventions SET {','.join(sets)} WHERE id=?",params)
    db.commit()
    if "statut" in d and old and d["statut"]!=old["statut"]:
        try: notify(iid,f"Statut mis à jour : {d['statut']}")
        except: pass
    return jsonify({"ok":True})

@app.route("/api/interventions/<int:iid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_intervention(iid):
    db = get_db()
    db.execute("DELETE FROM interventions WHERE id=?",(iid,))
    db.commit(); return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# COMPTES RENDUS
# Règles :
#   - Tout le monde peut créer un CR (si n'existe pas)
#   - Seuls admin/manager peuvent modifier un CR existant
# ══════════════════════════════════════════════════════════
@app.route("/api/comptes_rendus/<int:iid>")
@require_auth
def get_cr(iid):
    db  = get_db()
    crs = rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at DESC",(iid,)))
    for cr in crs:
        cr["intervenants"] = rows(db.execute("""
            SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
            FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id
            WHERE ci.cr_id=?""",(cr["id"],)))
    return jsonify(crs)

@app.route("/api/comptes_rendus/<int:iid>", methods=["POST"])
@require_auth
def save_cr(iid):
    user  = request.user
    d     = request.json or {}
    db    = get_db()
    cr_id = d.get("cr_id")  # si fourni, on modifie ce CR

    if cr_id:
        # Modification d'un CR existant : admin/manager seulement
        if user["role"] == "technicien":
            return jsonify({"error":"Accès interdit — seul un manager peut modifier un CR existant"}),403
        cr_id = int(cr_id)
        sets,params=[],[]
        for f in ["date_intervention","observations","actions_realisees","mesures","recommandations","conclusion"]:
            if f in d: sets.append(f"{f}=?"); params.append(d[f])
        if "photos" in d: sets.append("photos=?"); params.append(json.dumps(d["photos"]) if d["photos"] else None)
        sets.append("updated_at=?"); params.append(now())
        params.append(cr_id)
        db.execute(f"UPDATE comptes_rendus SET {','.join(sets)} WHERE id=?",params)
    else:
        # Création d'un nouveau CR
        db.execute("""INSERT INTO comptes_rendus
            (intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,photos)
            VALUES (?,?,?,?,?,?,?,?)""",
            (iid, d.get("date_intervention",today()),
             d.get("observations",""), d.get("actions_realisees",""),
             d.get("mesures",""), d.get("recommandations",""), d.get("conclusion",""),
             json.dumps(d["photos"]) if d.get("photos") else None))
        cr_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Intervenants
    if "intervenants" in d:
        db.execute("DELETE FROM cr_intervenants WHERE cr_id=?",(cr_id,))
        total = 0.0
        for iv in d["intervenants"]:
            uid = to_int(iv.get("utilisateur_id"))
            nom = str(iv.get("nom") or "")
            h   = 0.0
            hd  = iv.get("heure_debut","")
            hf  = iv.get("heure_fin","")
            if hd and hf:
                try:
                    a = datetime.strptime(hd,"%H:%M")
                    b = datetime.strptime(hf,"%H:%M")
                    h = max(0,(b-a).seconds/3600)
                except: pass
            db.execute("INSERT INTO cr_intervenants (cr_id,utilisateur_id,nom,date,heure_debut,heure_fin,total_heures) VALUES (?,?,?,?,?,?,?)",
                       (cr_id, uid, nom, iv.get("date",today()), hd, hf, round(h,2)))
            total += h
        db.execute("UPDATE comptes_rendus SET total_heures=? WHERE id=?",(round(total,2),cr_id))

    db.commit()
    return jsonify({"id":cr_id,"ok":True}),201

@app.route("/api/comptes_rendus/cr/<int:cr_id>", methods=["DELETE"])
@require_role("admin","manager")
def delete_cr(cr_id):
    db = get_db()
    db.execute("DELETE FROM comptes_rendus WHERE id=?",(cr_id,))
    db.commit()
    return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════
@app.route("/api/dashboard")
@require_auth
def dashboard():
    db   = get_db()
    user = request.user
    where, params = "WHERE 1=1", []
    if user["role"]=="technicien":
        eq_ids = [r[0] for r in db.execute(
            "SELECT equipe_id FROM equipe_membres WHERE technicien_id=?", (user["id"],)).fetchall()]
        if eq_ids:
            ph = ",".join(["?"]*len(eq_ids))
            where += " AND (i.technicien_id=? OR i.equipe_id IN ("+ph+"))"
            params.append(user["id"])
            params.extend(eq_ids)
        else:
            where += " AND i.technicien_id=?"; params.append(user["id"])
    elif user["role"]=="manager":
        where += " AND p.manager_id=?"; params.append(user["id"])

    base = f"""FROM interventions i JOIN equipements e ON i.equipement_id=e.id JOIN projets p ON e.projet_id=p.id {where}"""

    kpi = one(db.execute(f"""SELECT
        SUM(CASE WHEN i.statut='A_PLANIFIER' THEN 1 ELSE 0 END) AS a_planifier,
        SUM(CASE WHEN i.statut='PLANIFIEE'   THEN 1 ELSE 0 END) AS planifiees,
        SUM(CASE WHEN i.statut='EN_COURS'    THEN 1 ELSE 0 END) AS en_cours,
        SUM(CASE WHEN i.statut='TERMINEE'    THEN 1 ELSE 0 END) AS terminees
        {base}""",params))

    today_iv = rows(db.execute(f"""SELECT i.numero,i.type,i.statut,e.designation,p.nom AS projet
        {base} AND DATE(i.date_prevue)=? AND i.statut NOT IN ('TERMINEE','ANNULEE')
        ORDER BY i.date_prevue""",params+[today()]))

    retards = rows(db.execute(f"""SELECT i.numero,i.type,i.date_prevue,e.designation,p.nom AS projet
        {base} AND i.date_prevue<? AND i.statut NOT IN ('TERMINEE','ANNULEE')
        ORDER BY i.date_prevue""",params+[today()]))

    alertes = rows(db.execute("""SELECT p.type_piece,p.statut,p.date_fin_de_vie,
        e.designation AS equip_nom,pj.nom AS projet
        FROM pieces p JOIN equipements e ON p.equipement_id=e.id JOIN projets pj ON e.projet_id=pj.id
        WHERE p.statut IN ('A_SURVEILLER','A_REMPLACER') ORDER BY p.date_fin_de_vie"""))

    eq_all = rows(db.execute("SELECT e.id,e.designation,e.type_technique,p.nom AS projet FROM equipements e JOIN projets p ON e.projet_id=p.id"))
    critiques = [e for e in eq_all if criticite(e["id"],db)=="CRITIQUE"]

    dep = rows(db.execute(f"""SELECT JULIANDAY(i.date_realisation)-JULIANDAY(i.date_creation) AS delta
        {base} AND i.type='DEPANNAGE' AND i.statut='TERMINEE' AND i.date_realisation IS NOT NULL""",params))
    mnt = rows(db.execute(f"""SELECT JULIANDAY(i.date_realisation)-JULIANDAY(i.date_prevue) AS delta
        {base} AND i.type='MAINTENANCE' AND i.statut='TERMINEE' AND i.date_realisation IS NOT NULL AND i.date_prevue IS NOT NULL""",params))

    moy_dep = round(sum(r["delta"] for r in dep if r["delta"])/len(dep),1) if dep else 0
    moy_mnt = round(sum(r["delta"] for r in mnt if r["delta"])/len(mnt),1) if mnt else 0

    return jsonify({"kpi":kpi,"today":today_iv,"retards":retards,"alertes":alertes,
                    "critiques":critiques[:10],
                    "stats":{"moy_jours_depannage":moy_dep,"nb_depannages":len(dep),
                             "moy_jours_maintenance":moy_mnt,"nb_maintenances":len(mnt)}})

# ══════════════════════════════════════════════════════════
# SMTP
# ══════════════════════════════════════════════════════════
@app.route("/api/smtp")
@require_auth
def get_smtp():
    r = one(get_db().execute("SELECT host,port,username,use_tls,sender_email,sender_name,enabled FROM smtp_config WHERE id=1"))
    return jsonify(r or {})

@app.route("/api/smtp", methods=["POST"])
@require_role("admin")
def save_smtp():
    d = request.json or {}
    db = get_db()
    db.execute("UPDATE smtp_config SET host=?,port=?,username=?,password=?,use_tls=?,sender_email=?,sender_name=?,enabled=? WHERE id=1",
               (d.get("host",""),int(d.get("port",587)),d.get("username",""),d.get("password",""),
                1 if d.get("use_tls",True) else 0,d.get("sender_email",""),d.get("sender_name","SOCOM GMAO"),
                1 if d.get("enabled") else 0))
    db.commit(); return jsonify({"ok":True})

@app.route("/api/smtp/test", methods=["POST"])
@require_role("admin")
def test_smtp():
    d = request.json or {}
    if not d.get("to"): return jsonify({"error":"Email requis"}),400
    send_mail(d["to"],"[GMAO] Test SMTP","Test configuration SMTP — OK")
    return jsonify({"ok":True})

# ══════════════════════════════════════════════════════════
# EXPORT EXCEL
# ══════════════════════════════════════════════════════════

@app.route("/api/import/excel", methods=["POST"])
@require_role("admin","manager")
def import_excel():
    try:
        import openpyxl, io
        f = request.files.get("file")
        if not f: return jsonify({"error":"Fichier requis"}),400
        wb = openpyxl.load_workbook(io.BytesIO(f.read()), read_only=True)
        db = get_db()

        def get_rows(sheet_name):
            if sheet_name not in wb.sheetnames: return []
            ws   = wb[sheet_name]
            hdrs = [cell.value for cell in next(ws.iter_rows(min_row=1,max_row=1))]
            return [dict(zip(hdrs, row)) for row in ws.iter_rows(min_row=2, values_only=True)]

        # Ordre d'import respectant les FK
        # 1. Clients
        db.execute("DELETE FROM clients")
        for r in get_rows("Clients"):
            if not r.get("id"): continue
            db.execute("INSERT OR REPLACE INTO clients (id,societe,nom,prenom,email,telephone,notes,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (r["id"],r.get("societe",""),r.get("nom",""),r.get("prenom",""),r.get("email",""),r.get("telephone",""),r.get("notes",""),r.get("created_at",now())))

        # 2. Utilisateurs (hors admin)
        for r in get_rows("Utilisateurs"):
            if not r.get("id") or r.get("email")=="admin@gmao.fr": continue
            db.execute("INSERT OR REPLACE INTO utilisateurs (id,nom,email,password,role,actif,created_at) VALUES (?,?,?,?,?,?,?)",
                (r["id"],r.get("nom",""),r.get("email",""),r.get("password",hp("gmao2024")),r.get("role","technicien"),r.get("actif",1),r.get("created_at",now())))

        # 3. Projets
        db.execute("DELETE FROM projets")
        for r in get_rows("Projets"):
            if not r.get("id"): continue
            db.execute("INSERT OR REPLACE INTO projets (id,numero_projet,nom,client_id,manager_id,description,date_debut,date_fin,statut,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (r["id"],r.get("numero_projet",""),r.get("nom",""),r.get("client_id"),r.get("manager_id") or None,r.get("description",""),r.get("date_debut") or None,r.get("date_fin") or None,r.get("statut","EN_COURS"),r.get("created_at",now())))

        # 4. Equipements
        db.execute("DELETE FROM equipements")
        for r in get_rows("Equipements"):
            if not r.get("id"): continue
            db.execute("INSERT OR REPLACE INTO equipements (id,projet_id,designation,type_technique,localisation,marque,modele,puissance,numero_serie,in_out,date_mise_en_service,statut,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["id"],r.get("projet_id"),r.get("designation",""),r.get("type_technique","UPS"),r.get("localisation",""),r.get("marque",""),r.get("modele",""),r.get("puissance",""),r.get("numero_serie",""),r.get("in_out",""),r.get("date_mise_en_service") or None,r.get("statut","EN_SERVICE"),r.get("notes",""),r.get("created_at",now())))

        # 5. Pieces
        db.execute("DELETE FROM pieces")
        for r in get_rows("Pieces"):
            if not r.get("id"): continue
            db.execute("INSERT OR REPLACE INTO pieces (id,equipement_id,type_piece,date_installation,duree_vie_estimee,date_fin_de_vie,statut,commentaire,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (r["id"],r.get("equipement_id"),r.get("type_piece","BATTERIES"),r.get("date_installation") or None,r.get("duree_vie_estimee") or None,r.get("date_fin_de_vie") or None,r.get("statut","OK"),r.get("commentaire",""),r.get("created_at",now())))

        # 6. Interventions
        db.execute("DELETE FROM interventions")
        for r in get_rows("Interventions"):
            if not r.get("id"): continue
            db.execute("INSERT OR REPLACE INTO interventions (id,numero,equipement_id,technicien_id,type,statut,date_creation,date_prevue,date_realisation,description,rapport,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["id"],r.get("numero",""),r.get("equipement_id"),r.get("technicien_id") or None,r.get("type","MAINTENANCE"),r.get("statut","A_PLANIFIER"),r.get("date_creation",now()),r.get("date_prevue") or None,r.get("date_realisation") or None,r.get("description",""),r.get("rapport",""),r.get("created_at",now()),r.get("updated_at",now())))

        # 7. Comptes rendus
        db.execute("DELETE FROM comptes_rendus")
        for r in get_rows("CR"):
            if not r.get("id"): continue
            db.execute("INSERT OR REPLACE INTO comptes_rendus (id,intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,total_heures,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (r["id"],r.get("intervention_id"),r.get("date_intervention") or None,r.get("observations",""),r.get("actions_realisees",""),r.get("mesures",""),r.get("recommandations",""),r.get("conclusion",""),r.get("total_heures",0),r.get("created_at",now()),r.get("updated_at",now())))

        db.commit()
        return jsonify({"ok":True,"message":"Import termine avec succes"})
    except ImportError:
        return jsonify({"error":"openpyxl non installe"}),500
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route("/api/export/excel")
@require_auth
def export_excel():
    try:
        import openpyxl
        db = get_db()
        wb = openpyxl.Workbook()
        sheets = [
            ("Clients",        "SELECT id,societe,nom,prenom,email,telephone,notes,created_at FROM clients"),
            ("Utilisateurs",   "SELECT id,nom,email,password,role,actif,created_at FROM utilisateurs"),
            ("Projets",        "SELECT id,numero_projet,nom,client_id,manager_id,description,date_debut,date_fin,statut,created_at FROM projets"),
            ("Equipements",    "SELECT id,projet_id,designation,type_technique,localisation,marque,modele,puissance,numero_serie,in_out,date_mise_en_service,statut,notes,created_at FROM equipements"),
            ("Pieces",         "SELECT id,equipement_id,type_piece,date_installation,duree_vie_estimee,date_fin_de_vie,statut,commentaire,created_at FROM pieces"),
            ("Interventions",  "SELECT id,numero,equipement_id,technicien_id,type,statut,date_creation,date_prevue,date_realisation,description,rapport,created_at,updated_at FROM interventions"),
            ("CR",             "SELECT id,intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,total_heures,created_at,updated_at FROM comptes_rendus"),
            ("CR_Intervenants","SELECT id,cr_id,utilisateur_id,nom,date,heure_debut,heure_fin,total_heures FROM cr_intervenants"),
            ("Equipes",        "SELECT id,nom,manager_id,created_at FROM equipes"),
        ]
        first = True
        for name, sql in sheets:
            try:
                rs = db.execute(sql).fetchall()
                ws = wb.active if first else wb.create_sheet(name)
                if first: ws.title = name; first = False
                if rs:
                    ws.append([d[0] for d in db.execute(sql).description])
                    for row in rs: ws.append(list(row))
                else:
                    ws.append([d[0] for d in db.execute(sql).description])
            except: continue
        buf = io.BytesIO(); wb.save(buf); buf.seek(0)
        return send_file(buf,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True, download_name="gmao_backup.xlsx")
    except ImportError:
        return jsonify({"error":"openpyxl non installe"}),500
    except Exception as e:
        return jsonify({"error":str(e)}),500


