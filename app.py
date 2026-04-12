"""
SOCOM GMAO — Backend Flask v2.0
================================
Rôles :
  admin      → accès total
  manager    → voit les BT de ses projets, peut créer/modifier CR
  technicien → voit ses BT assignés, peut créer BT, lit les CR
"""

import hashlib, json, os, sqlite3, smtplib, io
from datetime import datetime, date, timedelta
from functools import wraps
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from flask import Flask, jsonify, request, send_file, Response
    from flask_cors import CORS
except ImportError:
    raise ImportError("pip install flask flask-cors")

# ══════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════
BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.environ.get("GMAO_DB", str(BASE_DIR / "gmao.db"))

app = Flask(__name__)
CORS(app, origins="*")

# ══════════════════════════════════════════════════════════
# DB
# ══════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        nom        TEXT NOT NULL,
        email      TEXT NOT NULL UNIQUE,
        password   TEXT NOT NULL,
        role       TEXT NOT NULL DEFAULT 'technicien'
                   CHECK(role IN ('admin','manager','technicien')),
        actif      INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS clients (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        societe    TEXT NOT NULL,
        nom        TEXT,
        prenom     TEXT,
        email      TEXT,
        telephone  TEXT,
        notes      TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS projets (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        numero_projet     TEXT NOT NULL UNIQUE,
        nom               TEXT NOT NULL,
        client_id         INTEGER NOT NULL REFERENCES clients(id),
        manager_id        INTEGER REFERENCES utilisateurs(id),
        description       TEXT,
        date_debut        TEXT,
        date_fin          TEXT,
        statut            TEXT NOT NULL DEFAULT 'EN_COURS'
                          CHECK(statut IN ('EN_COURS','TERMINE','SUSPENDU')),
        created_at        TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS equipements (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        projet_id            INTEGER NOT NULL REFERENCES projets(id),
        designation          TEXT NOT NULL,
        type_technique       TEXT NOT NULL
                             CHECK(type_technique IN (
                               'UPS','STS','HAUTE_TENSION','GROUPE_ELECTROGENE',
                               'ECLAIRAGE_SECOURS','DETECTION_INCENDIE','DESENFUMAGE'
                             )),
        localisation         TEXT,
        marque               TEXT,
        modele               TEXT,
        puissance            TEXT,
        numero_serie         TEXT,
        in_out               TEXT,
        date_mise_en_service TEXT,
        statut               TEXT NOT NULL DEFAULT 'EN_SERVICE'
                             CHECK(statut IN ('EN_SERVICE','HORS_SERVICE')),
        notes                TEXT,
        created_at           TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS pieces (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        equipement_id       INTEGER NOT NULL REFERENCES equipements(id) ON DELETE CASCADE,
        type_piece          TEXT NOT NULL
                            CHECK(type_piece IN (
                              'BATTERIES','VENTILATEURS','CONDENSATEURS_AC',
                              'CONDENSATEURS_DC','CARTE_ALIMENTATION'
                            )),
        date_installation   TEXT,
        duree_vie_estimee   INTEGER,
        date_fin_de_vie     TEXT,
        statut              TEXT NOT NULL DEFAULT 'OK'
                            CHECK(statut IN ('OK','A_SURVEILLER','A_REMPLACER')),
        commentaire         TEXT,
        created_at          TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS equipes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        nom        TEXT NOT NULL UNIQUE,
        manager_id INTEGER REFERENCES utilisateurs(id),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS equipe_membres (
        equipe_id     INTEGER NOT NULL REFERENCES equipes(id) ON DELETE CASCADE,
        technicien_id INTEGER NOT NULL REFERENCES utilisateurs(id),
        PRIMARY KEY (equipe_id, technicien_id)
    );

    CREATE TABLE IF NOT EXISTS interventions (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        numero           TEXT NOT NULL UNIQUE,
        equipement_id    INTEGER NOT NULL REFERENCES equipements(id),
        technicien_id    INTEGER REFERENCES utilisateurs(id),
        type             TEXT NOT NULL CHECK(type IN ('MAINTENANCE','DEPANNAGE')),
        statut           TEXT NOT NULL DEFAULT 'A_PLANIFIER'
                         CHECK(statut IN ('A_PLANIFIER','PLANIFIEE','EN_COURS','TERMINEE','ANNULEE')),
        date_creation    TEXT NOT NULL DEFAULT (datetime('now')),
        date_prevue      TEXT,
        date_realisation TEXT,
        description      TEXT,
        rapport          TEXT,
        created_at       TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS comptes_rendus (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        intervention_id   INTEGER NOT NULL UNIQUE REFERENCES interventions(id) ON DELETE CASCADE,
        date_intervention TEXT,
        observations      TEXT,
        actions_realisees TEXT,
        mesures           TEXT,
        recommandations   TEXT,
        conclusion        TEXT,
        total_heures      REAL DEFAULT 0,
        photos            TEXT,
        created_at        TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS cr_intervenants (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        cr_id          INTEGER NOT NULL REFERENCES comptes_rendus(id) ON DELETE CASCADE,
        utilisateur_id INTEGER REFERENCES utilisateurs(id),
        nom            TEXT,
        date           TEXT,
        heure_debut    TEXT,
        heure_fin      TEXT,
        total_heures   REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS smtp_config (
        id           INTEGER PRIMARY KEY CHECK(id=1),
        host         TEXT DEFAULT '',
        port         INTEGER DEFAULT 587,
        username     TEXT DEFAULT '',
        password     TEXT DEFAULT '',
        use_tls      INTEGER DEFAULT 1,
        sender_email TEXT DEFAULT '',
        sender_name  TEXT DEFAULT 'SOCOM GMAO',
        enabled      INTEGER DEFAULT 0
    );

    INSERT OR IGNORE INTO smtp_config (id) VALUES (1);
    """)
    db.commit()
    # Admin par défaut
    pw = hashlib.sha256("admin".encode()).hexdigest()
    try:
        db.execute("INSERT OR IGNORE INTO utilisateurs (nom,email,password,role) VALUES (?,?,?,?)",
                   ("Administrateur","admin@gmao.fr",pw,"admin"))
        db.commit()
    except: pass
    db.close()

# ══════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════
def hp(p):   return hashlib.sha256(p.encode()).hexdigest()
def now():   return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def today(): return date.today().isoformat()
def rows(cur): return [dict(r) for r in cur.fetchall()]
def one(cur):  r = cur.fetchone(); return dict(r) if r else None

def calc_fin_de_vie(date_install, duree_ans):
    try:
        d = datetime.strptime(date_install, "%Y-%m-%d")
        return (d + timedelta(days=int(duree_ans)*365)).strftime("%Y-%m-%d")
    except: return None

def calc_statut_piece(date_fdv):
    if not date_fdv: return "OK"
    try:
        fdv   = datetime.strptime(date_fdv, "%Y-%m-%d").date()
        delta = (fdv - date.today()).days
        if delta < 0:   return "A_REMPLACER"
        if delta < 180: return "A_SURVEILLER"
        return "OK"
    except: return "OK"

def criticite_equipement(equip_id, db):
    pieces = rows(db.execute("SELECT statut FROM pieces WHERE equipement_id=?", (equip_id,)))
    if any(p["statut"] == "A_REMPLACER"  for p in pieces): return "CRITIQUE"
    if any(p["statut"] == "A_SURVEILLER" for p in pieces): return "ATTENTION"
    return "OK"

def gen_numero(db, prefix, table):
    n = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] + 1
    return f"{prefix}{n:05d}"

# ══════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════
def check_auth():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return None
    token = auth[7:]
    if ":" not in token: return None
    uid, pw = token.split(":",1)
    try:
        db = get_db()
        r  = one(db.execute(
            "SELECT id,nom,email,role FROM utilisateurs WHERE id=? AND password=? AND actif=1",
            (uid, pw)))
        return r
    except: return None

def require_auth(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        u = check_auth()
        if not u: return jsonify({"error":"Non autorisé"}), 401
        request.user = u
        return fn(*a, **kw)
    return wrap

def require_role(*roles):
    def dec(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            u = check_auth()
            if not u: return jsonify({"error":"Non autorisé"}), 401
            if u["role"] not in roles:
                return jsonify({"error":"Accès interdit"}), 403
            request.user = u
            return fn(*a, **kw)
        return wrap
    return dec

# ══════════════════════════════════════════════════════════
# MAIL
# ══════════════════════════════════════════════════════════
def send_mail(to, subject, body):
    try:
        db  = get_db()
        cfg = one(db.execute("SELECT * FROM smtp_config WHERE id=1"))
        if not cfg or not cfg["enabled"]: return False
        msg = MIMEMultipart()
        msg["From"]    = f"{cfg['sender_name']} <{cfg['sender_email']}>"
        msg["To"]      = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as srv:
            if cfg["use_tls"]: srv.starttls()
            if cfg["username"]: srv.login(cfg["username"], cfg["password"])
            srv.sendmail(cfg["sender_email"], to, msg.as_string())
        return True
    except Exception as e:
        print(f"[MAIL] {e}"); return False

def notify_intervention(interv_id, action):
    try:
        db = get_db()
        r  = one(db.execute("""
            SELECT i.numero, i.type, i.statut, e.designation,
                   p.nom AS projet, u.email AS mgr_email, u.nom AS mgr_nom
            FROM interventions i
            JOIN equipements e   ON i.equipement_id = e.id
            JOIN projets p       ON e.projet_id = p.id
            LEFT JOIN utilisateurs u ON p.manager_id = u.id
            WHERE i.id=?""", (interv_id,)))
        if not r or not r["mgr_email"]: return
        send_mail(r["mgr_email"],
            f"[GMAO] {action} — {r['numero']}",
            f"Bonjour {r['mgr_nom']},\n\n{action}\n\n"
            f"Intervention : {r['numero']}\n"
            f"Type         : {r['type']}\n"
            f"Statut       : {r['statut']}\n"
            f"Equipement   : {r['designation']}\n"
            f"Projet       : {r['projet']}\n\n"
            f"Cordialement,\nSOCOM GMAO")
    except Exception as e:
        print(f"[NOTIFY] {e}")

# ══════════════════════════════════════════════════════════
# FRONTEND
# ══════════════════════════════════════════════════════════
@app.route("/")
def index():
    f = BASE_DIR / "index.html"
    if f.exists(): return send_file(str(f))
    return "<h1>index.html introuvable</h1>", 404

@app.route("/mobile")
def mobile():
    f = BASE_DIR / "gmao_mobile.html"
    if f.exists(): return send_file(str(f))
    return "<h1>gmao_mobile.html introuvable</h1>", 404

@app.route("/sw.js")
def sw():
    f = BASE_DIR / "sw.js"
    if f.exists():
        return Response(f.read_text(), mimetype="application/javascript",
                        headers={"Service-Worker-Allowed": "/"})
    return "// sw not found", 404

@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "GMAO Terrain", "short_name": "GMAO",
        "start_url": "/mobile", "display": "standalone",
        "background_color": "#1e293b", "theme_color": "#3b82f6",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ]
    })

@app.route("/health")
def health():
    try:
        db = get_db(); db.execute("SELECT 1")
        return jsonify({"status": "ok", "time": now()})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

# ══════════════════════════════════════════════════════════
# API AUTH
# ══════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def login():
    d  = request.json or {}
    em = (d.get("email") or "").strip()
    pw = (d.get("password") or "").strip()
    if not em or not pw:
        return jsonify({"error": "Identifiants manquants"}), 400
    try:
        db = get_db()
        r  = one(db.execute(
            "SELECT id,nom,email,role FROM utilisateurs WHERE email=? AND password=? AND actif=1",
            (em, hp(pw))))
        if not r: return jsonify({"error": "Identifiants incorrects"}), 401
        r["token"] = f"{r['id']}:{hp(pw)}"
        return jsonify(r)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════
# API UTILISATEURS
# ══════════════════════════════════════════════════════════
@app.route("/api/utilisateurs")
@require_auth
def get_utilisateurs():
    db = get_db()
    return jsonify(rows(db.execute(
        "SELECT id,nom,email,role,actif FROM utilisateurs ORDER BY nom")))

@app.route("/api/utilisateurs", methods=["POST"])
@require_role("admin")
def create_utilisateur():
    d = request.json or {}
    if not d.get("nom") or not d.get("email") or not d.get("password"):
        return jsonify({"error": "nom, email et password requis"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO utilisateurs (nom,email,password,role) VALUES (?,?,?,?)",
            (d["nom"], d["email"], hp(d["password"]), d.get("role","technicien")))
        db.commit()
        return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/utilisateurs/<int:uid>", methods=["PATCH"])
@require_role("admin")
def update_utilisateur(uid):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["nom","email","role","actif"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if "password" in d and d["password"]:
        sets.append("password=?"); params.append(hp(d["password"]))
    if not sets: return jsonify({"error": "Rien"}), 400
    params.append(uid)
    db.execute(f"UPDATE utilisateurs SET {','.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════
# API CLIENTS
# ══════════════════════════════════════════════════════════
@app.route("/api/clients")
@require_auth
def get_clients():
    return jsonify(rows(get_db().execute("SELECT * FROM clients ORDER BY societe")))

@app.route("/api/clients", methods=["POST"])
@require_auth
def create_client():
    d = request.json or {}
    if not d.get("societe"): return jsonify({"error": "societe requis"}), 400
    db = get_db()
    db.execute("INSERT INTO clients (societe,nom,prenom,email,telephone,notes) VALUES (?,?,?,?,?,?)",
        (d["societe"],d.get("nom",""),d.get("prenom",""),d.get("email",""),
         d.get("telephone",""),d.get("notes","")))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201

@app.route("/api/clients/<int:cid>", methods=["PATCH"])
@require_auth
def update_client(cid):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["societe","nom","prenom","email","telephone","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error": "Rien"}), 400
    params.append(cid)
    db.execute(f"UPDATE clients SET {','.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/clients/<int:cid>", methods=["DELETE"])
@require_role("admin")
def delete_client(cid):
    db = get_db()
    db.execute("DELETE FROM clients WHERE id=?", (cid,))
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════
# API PROJETS
# ══════════════════════════════════════════════════════════
@app.route("/api/projets")
@require_auth
def get_projets():
    db   = get_db()
    user = request.user
    sql  = """
        SELECT p.*, c.societe AS client_nom, u.nom AS manager_nom
        FROM projets p
        LEFT JOIN clients c ON p.client_id = c.id
        LEFT JOIN utilisateurs u ON p.manager_id = u.id
        WHERE 1=1"""
    params = []
    if user["role"] == "manager":
        sql += " AND p.manager_id=?"; params.append(user["id"])
    elif user["role"] == "technicien":
        # Technicien voit les projets sur lesquels il a des interventions
        sql += """ AND p.id IN (
            SELECT DISTINCT e.projet_id FROM interventions i
            JOIN equipements e ON i.equipement_id = e.id
            WHERE i.technicien_id=?)"""
        params.append(user["id"])
    sql += " ORDER BY p.nom"
    return jsonify(rows(db.execute(sql, params)))

@app.route("/api/projets/<int:pid>")
@require_auth
def get_projet(pid):
    db = get_db()
    p  = one(db.execute("""
        SELECT p.*, c.societe AS client_nom, u.nom AS manager_nom
        FROM projets p
        LEFT JOIN clients c ON p.client_id = c.id
        LEFT JOIN utilisateurs u ON p.manager_id = u.id
        WHERE p.id=?""", (pid,)))
    if not p: return jsonify({"error": "Non trouvé"}), 404
    p["equipements"] = rows(db.execute(
        "SELECT id,designation,type_technique,statut FROM equipements WHERE projet_id=?", (pid,)))
    for e in p["equipements"]:
        e["criticite"] = criticite_equipement(e["id"], db)
    return jsonify(p)

@app.route("/api/projets", methods=["POST"])
@require_role("admin","manager")
def create_projet():
    d = request.json or {}
    if not d.get("nom") or not d.get("client_id"):
        return jsonify({"error": "nom et client_id requis"}), 400
    db  = get_db()
    num = d.get("numero_projet") or gen_numero(db, "PRJ", "projets")
    try:
        db.execute("""INSERT INTO projets
            (numero_projet,nom,client_id,manager_id,description,date_debut,date_fin,statut)
            VALUES (?,?,?,?,?,?,?,?)""",
            (num, d["nom"], d["client_id"],
             d.get("manager_id") or None, d.get("description",""),
             d.get("date_debut") or None, d.get("date_fin") or None,
             d.get("statut","EN_COURS")))
        db.commit()
        return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0], "numero": num}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/projets/<int:pid>", methods=["PATCH"])
@require_role("admin","manager")
def update_projet(pid):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["nom","client_id","manager_id","description","date_debut","date_fin","statut","numero_projet"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f] or None)
    if not sets: return jsonify({"error": "Rien"}), 400
    params.append(pid)
    db.execute(f"UPDATE projets SET {','.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/projets/<int:pid>", methods=["DELETE"])
@require_role("admin")
def delete_projet(pid):
    db = get_db()
    db.execute("DELETE FROM projets WHERE id=?", (pid,))
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════
# API EQUIPEMENTS
# ══════════════════════════════════════════════════════════
@app.route("/api/equipements")
@require_auth
def get_equipements():
    db   = get_db()
    user = request.user
    sql  = """
        SELECT e.*, p.nom AS projet_nom, p.numero_projet
        FROM equipements e
        JOIN projets p ON e.projet_id = p.id
        WHERE 1=1"""
    params = []
    if request.args.get("projet_id"):
        sql += " AND e.projet_id=?"; params.append(request.args["projet_id"])
    if user["role"] == "manager":
        sql += " AND p.manager_id=?"; params.append(user["id"])
    elif user["role"] == "technicien":
        sql += """ AND e.projet_id IN (
            SELECT DISTINCT e2.projet_id FROM interventions i
            JOIN equipements e2 ON i.equipement_id = e2.id
            WHERE i.technicien_id=?)"""
        params.append(user["id"])
    sql += " ORDER BY p.nom, e.designation"
    equips = rows(db.execute(sql, params))
    for e in equips:
        e["criticite"] = criticite_equipement(e["id"], db)
    return jsonify(equips)

@app.route("/api/equipements/<int:eid>")
@require_auth
def get_equipement(eid):
    db = get_db()
    e  = one(db.execute("""
        SELECT e.*, p.nom AS projet_nom, p.numero_projet
        FROM equipements e JOIN projets p ON e.projet_id = p.id
        WHERE e.id=?""", (eid,)))
    if not e: return jsonify({"error": "Non trouvé"}), 404
    e["pieces"]    = rows(db.execute("SELECT * FROM pieces WHERE equipement_id=? ORDER BY type_piece", (eid,)))
    e["criticite"] = criticite_equipement(eid, db)
    return jsonify(e)

@app.route("/api/equipements", methods=["POST"])
@require_role("admin","manager")
def create_equipement():
    d = request.json or {}
    if not d.get("designation") or not d.get("projet_id") or not d.get("type_technique"):
        return jsonify({"error": "designation, projet_id et type_technique requis"}), 400
    db = get_db()
    db.execute("""INSERT INTO equipements
        (projet_id,designation,type_technique,localisation,marque,modele,
         puissance,numero_serie,in_out,date_mise_en_service,statut,notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (d["projet_id"], d["designation"], d["type_technique"],
         d.get("localisation",""), d.get("marque",""), d.get("modele",""),
         d.get("puissance",""), d.get("numero_serie",""), d.get("in_out",""),
         d.get("date_mise_en_service") or None,
         d.get("statut","EN_SERVICE"), d.get("notes","")))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201

@app.route("/api/equipements/<int:eid>", methods=["PATCH"])
@require_role("admin","manager")
def update_equipement(eid):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["designation","type_technique","localisation","marque","modele",
              "puissance","numero_serie","in_out","date_mise_en_service","statut","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error": "Rien"}), 400
    params.append(eid)
    db.execute(f"UPDATE equipements SET {','.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/equipements/<int:eid>", methods=["DELETE"])
@require_role("admin")
def delete_equipement(eid):
    db = get_db()
    db.execute("DELETE FROM equipements WHERE id=?", (eid,))
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════
# API PIECES
# ══════════════════════════════════════════════════════════
@app.route("/api/pieces")
@require_auth
def get_pieces():
    db  = get_db()
    sql = """
        SELECT p.*, e.designation AS equip_nom, pj.nom AS projet_nom
        FROM pieces p
        JOIN equipements e ON p.equipement_id = e.id
        JOIN projets pj    ON e.projet_id = pj.id
        WHERE 1=1"""
    params = []
    if request.args.get("equipement_id"):
        sql += " AND p.equipement_id=?"; params.append(request.args["equipement_id"])
    if request.args.get("alertes"):
        sql += " AND p.statut IN ('A_SURVEILLER','A_REMPLACER')"
    sql += " ORDER BY p.date_fin_de_vie"
    return jsonify(rows(db.execute(sql, params)))

@app.route("/api/pieces", methods=["POST"])
@require_role("admin","manager")
def create_piece():
    d = request.json or {}
    if not d.get("equipement_id") or not d.get("type_piece"):
        return jsonify({"error": "equipement_id et type_piece requis"}), 400
    fdv    = None
    if d.get("date_installation") and d.get("duree_vie_estimee"):
        fdv = calc_fin_de_vie(d["date_installation"], d["duree_vie_estimee"])
    statut = d.get("statut") or calc_statut_piece(fdv)
    db     = get_db()
    db.execute("""INSERT INTO pieces
        (equipement_id,type_piece,date_installation,duree_vie_estimee,date_fin_de_vie,statut,commentaire)
        VALUES (?,?,?,?,?,?,?)""",
        (d["equipement_id"], d["type_piece"],
         d.get("date_installation") or None,
         d.get("duree_vie_estimee") or None,
         fdv, statut, d.get("commentaire","")))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201

@app.route("/api/pieces/<int:pid>", methods=["PATCH"])
@require_role("admin","manager")
def update_piece(pid):
    d  = request.json or {}
    db = get_db()
    p  = one(db.execute("SELECT * FROM pieces WHERE id=?", (pid,)))
    date_inst = d.get("date_installation", p["date_installation"] if p else None)
    duree     = d.get("duree_vie_estimee", p["duree_vie_estimee"] if p else None)
    if date_inst and duree:
        d["date_fin_de_vie"] = calc_fin_de_vie(date_inst, int(duree))
        if "statut" not in d:
            d["statut"] = calc_statut_piece(d["date_fin_de_vie"])
    sets, params = [], []
    for f in ["type_piece","date_installation","duree_vie_estimee","date_fin_de_vie","statut","commentaire"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error": "Rien"}), 400
    params.append(pid)
    db.execute(f"UPDATE pieces SET {','.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/pieces/<int:pid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_piece(pid):
    db = get_db()
    db.execute("DELETE FROM pieces WHERE id=?", (pid,))
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════
# API EQUIPES
# ══════════════════════════════════════════════════════════
@app.route("/api/equipes")
@require_auth
def get_equipes():
    db     = get_db()
    equipes = rows(db.execute("""
        SELECT e.*, u.nom AS manager_nom
        FROM equipes e LEFT JOIN utilisateurs u ON e.manager_id = u.id
        ORDER BY e.nom"""))
    for eq in equipes:
        eq["membres"] = rows(db.execute("""
            SELECT u.id, u.nom, u.role FROM equipe_membres em
            JOIN utilisateurs u ON em.technicien_id = u.id
            WHERE em.equipe_id=?""", (eq["id"],)))
    return jsonify(equipes)

@app.route("/api/equipes", methods=["POST"])
@require_role("admin","manager")
def create_equipe():
    d = request.json or {}
    if not d.get("nom"): return jsonify({"error": "nom requis"}), 400
    db = get_db()
    db.execute("INSERT INTO equipes (nom,manager_id) VALUES (?,?)",
        (d["nom"], d.get("manager_id") or None))
    db.commit()
    eid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for mid in d.get("membres", []):
        try: db.execute("INSERT OR IGNORE INTO equipe_membres VALUES (?,?)", (eid, mid))
        except: pass
    db.commit()
    return jsonify({"id": eid}), 201

@app.route("/api/equipes/<int:eid>", methods=["PATCH"])
@require_role("admin","manager")
def update_equipe(eid):
    d = request.json or {}
    db = get_db()
    if "nom" in d or "manager_id" in d:
        sets, params = [], []
        if "nom" in d:        sets.append("nom=?");        params.append(d["nom"])
        if "manager_id" in d: sets.append("manager_id=?"); params.append(d["manager_id"] or None)
        params.append(eid)
        db.execute(f"UPDATE equipes SET {','.join(sets)} WHERE id=?", params)
    if "membres" in d:
        db.execute("DELETE FROM equipe_membres WHERE equipe_id=?", (eid,))
        for mid in d["membres"]:
            try: db.execute("INSERT OR IGNORE INTO equipe_membres VALUES (?,?)", (eid, mid))
            except: pass
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/equipes/<int:eid>", methods=["DELETE"])
@require_role("admin")
def delete_equipe(eid):
    db = get_db()
    db.execute("DELETE FROM equipes WHERE id=?", (eid,))
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════
# API INTERVENTIONS
# ══════════════════════════════════════════════════════════
@app.route("/api/interventions")
@require_auth
def get_interventions():
    db   = get_db()
    user = request.user
    sql  = """
        SELECT i.*, e.designation AS equip_nom, e.type_technique, e.localisation, e.projet_id,
               p.nom AS projet_nom, p.numero_projet,
               u.nom AS technicien_nom
        FROM interventions i
        JOIN equipements e   ON i.equipement_id = e.id
        JOIN projets p       ON e.projet_id = p.id
        LEFT JOIN utilisateurs u ON i.technicien_id = u.id
        WHERE 1=1"""
    params = []

    # Filtrage selon rôle
    if user["role"] == "technicien":
        sql += " AND i.technicien_id=?"; params.append(user["id"])
    elif user["role"] == "manager":
        sql += " AND p.manager_id=?"; params.append(user["id"])
    # admin voit tout

    # Filtres optionnels
    for arg, col in [("statut","i.statut"),("type","i.type"),
                     ("projet_id","e.projet_id"),("equipement_id","i.equipement_id")]:
        if request.args.get(arg):
            sql += f" AND {col}=?"; params.append(request.args[arg])
    if request.args.get("today"):
        sql += " AND DATE(i.date_prevue)=?"; params.append(today())

    sql += " ORDER BY i.date_creation DESC LIMIT 500"
    return jsonify(rows(db.execute(sql, params)))

@app.route("/api/interventions/<int:iid>")
@require_auth
def get_intervention(iid):
    db = get_db()
    i  = one(db.execute("""
        SELECT i.*, e.designation AS equip_nom, e.type_technique,
               e.localisation, e.projet_id,
               p.nom AS projet_nom, p.numero_projet,
               u.nom AS technicien_nom
        FROM interventions i
        JOIN equipements e   ON i.equipement_id = e.id
        JOIN projets p       ON e.projet_id = p.id
        LEFT JOIN utilisateurs u ON i.technicien_id = u.id
        WHERE i.id=?""", (iid,)))
    if not i: return jsonify({"error": "Non trouvé"}), 404
    # Compte rendu
    cr = one(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=?", (iid,)))
    if cr:
        cr["intervenants"] = rows(db.execute("""
            SELECT ci.*, COALESCE(u.nom, ci.nom) AS nom
            FROM cr_intervenants ci
            LEFT JOIN utilisateurs u ON ci.utilisateur_id = u.id
            WHERE ci.cr_id=?""", (cr["id"],)))
        i["compte_rendu"] = cr
    else:
        i["compte_rendu"] = None
    return jsonify(i)

@app.route("/api/interventions", methods=["POST"])
@require_auth
def create_intervention():
    user = request.user
    d    = request.json or {}
    if not d.get("equipement_id") or not d.get("type"):
        return jsonify({"error": "equipement_id et type requis"}), 400
    db  = get_db()
    num = gen_numero(db, "INT", "interventions")
    # Si technicien, s'assigne automatiquement
    tech_id = d.get("technicien_id") or (user["id"] if user["role"] == "technicien" else None)
    db.execute("""INSERT INTO interventions
        (numero,equipement_id,technicien_id,type,statut,date_prevue,description)
        VALUES (?,?,?,?,?,?,?)""",
        (num, d["equipement_id"], tech_id,
         d["type"], d.get("statut","A_PLANIFIER"),
         d.get("date_prevue") or None,
         d.get("description","")))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    try: notify_intervention(new_id, "Nouvelle intervention créée")
    except: pass
    return jsonify({"id": new_id, "numero": num}), 201

@app.route("/api/interventions/<int:iid>", methods=["PATCH"])
@require_auth
def update_intervention(iid):
    user = request.user
    d    = request.json or {}
    db   = get_db()
    old  = one(db.execute("SELECT statut FROM interventions WHERE id=?", (iid,)))
    sets, params = [], []
    for f in ["technicien_id","type","statut","date_prevue","date_realisation","description","rapport"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f] or None if f == "technicien_id" else d[f])
    if "statut" in d and d["statut"] == "TERMINEE" and "date_realisation" not in d:
        sets.append("date_realisation=?"); params.append(today())
    sets.append("updated_at=?"); params.append(now())
    params.append(iid)
    db.execute(f"UPDATE interventions SET {','.join(sets)} WHERE id=?", params)
    db.commit()
    if "statut" in d and old and d["statut"] != old["statut"]:
        try: notify_intervention(iid, f"Statut mis à jour : {d['statut']}")
        except: pass
    return jsonify({"ok": True})

@app.route("/api/interventions/<int:iid>", methods=["DELETE"])
@require_role("admin","manager")
def delete_intervention(iid):
    db = get_db()
    db.execute("DELETE FROM interventions WHERE id=?", (iid,))
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════
# API COMPTES RENDUS
# ══════════════════════════════════════════════════════════
@app.route("/api/comptes_rendus/<int:iid>")
@require_auth
def get_cr(iid):
    db = get_db()
    cr = one(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=?", (iid,)))
    if not cr: return jsonify(None)
    cr["intervenants"] = rows(db.execute("""
        SELECT ci.*, COALESCE(u.nom, ci.nom) AS nom
        FROM cr_intervenants ci
        LEFT JOIN utilisateurs u ON ci.utilisateur_id = u.id
        WHERE ci.cr_id=?""", (cr["id"],)))
    return jsonify(cr)

@app.route("/api/comptes_rendus/<int:iid>", methods=["POST"])
@require_role("admin","manager")
def create_or_update_cr(iid):
    d  = request.json or {}
    db = get_db()
    ex = one(db.execute("SELECT id FROM comptes_rendus WHERE intervention_id=?", (iid,)))
    if ex:
        cr_id = ex["id"]
        sets, params = [], []
        for f in ["date_intervention","observations","actions_realisees","mesures","recommandations","conclusion"]:
            if f in d: sets.append(f"{f}=?"); params.append(d[f])
        if "photos" in d: sets.append("photos=?"); params.append(json.dumps(d["photos"]))
        sets.append("updated_at=?"); params.append(now())
        params.append(cr_id)
        if sets: db.execute(f"UPDATE comptes_rendus SET {','.join(sets)} WHERE id=?", params)
    else:
        db.execute("""INSERT INTO comptes_rendus
            (intervention_id,date_intervention,observations,actions_realisees,
             mesures,recommandations,conclusion,photos)
            VALUES (?,?,?,?,?,?,?,?)""",
            (iid, d.get("date_intervention", today()),
             d.get("observations",""), d.get("actions_realisees",""),
             d.get("mesures",""), d.get("recommandations",""),
             d.get("conclusion",""),
             json.dumps(d.get("photos",[])) if d.get("photos") else None))
        cr_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Intervenants
    if "intervenants" in d:
        db.execute("DELETE FROM cr_intervenants WHERE cr_id=?", (cr_id,))
        total = 0.0
        for iv in d["intervenants"]:
            h = 0.0
            if iv.get("heure_debut") and iv.get("heure_fin"):
                try:
                    hd = datetime.strptime(iv["heure_debut"], "%H:%M")
                    hf = datetime.strptime(iv["heure_fin"],   "%H:%M")
                    h  = max(0, (hf - hd).seconds / 3600)
                except: pass
            db.execute("""INSERT INTO cr_intervenants
                (cr_id,utilisateur_id,nom,date,heure_debut,heure_fin,total_heures)
                VALUES (?,?,?,?,?,?,?)""",
                (cr_id,
                 iv.get("utilisateur_id") or None,
                 iv.get("nom",""),
                 iv.get("date", today()),
                 iv.get("heure_debut",""), iv.get("heure_fin",""),
                 round(h, 2)))
            total += h
        db.execute("UPDATE comptes_rendus SET total_heures=? WHERE id=?", (round(total,2), cr_id))

    db.commit()
    return jsonify({"id": cr_id, "ok": True}), 201

# ══════════════════════════════════════════════════════════
# API DASHBOARD
# ══════════════════════════════════════════════════════════
@app.route("/api/dashboard")
@require_auth
def dashboard():
    db   = get_db()
    user = request.user

    # Filtre selon rôle
    where  = "WHERE 1=1"
    params = []
    if user["role"] == "technicien":
        where += " AND i.technicien_id=?"; params.append(user["id"])
    elif user["role"] == "manager":
        where += """ AND e.projet_id IN (
            SELECT id FROM projets WHERE manager_id=?)"""
        params.append(user["id"])

    kpi = one(db.execute(f"""
        SELECT
          SUM(CASE WHEN i.statut='A_PLANIFIER' THEN 1 ELSE 0 END) AS a_planifier,
          SUM(CASE WHEN i.statut='PLANIFIEE'   THEN 1 ELSE 0 END) AS planifiees,
          SUM(CASE WHEN i.statut='EN_COURS'    THEN 1 ELSE 0 END) AS en_cours,
          SUM(CASE WHEN i.statut='TERMINEE'    THEN 1 ELSE 0 END) AS terminees,
          SUM(CASE WHEN i.type='MAINTENANCE'   THEN 1 ELSE 0 END) AS maintenance,
          SUM(CASE WHEN i.type='DEPANNAGE'     THEN 1 ELSE 0 END) AS depannage
        FROM interventions i
        JOIN equipements e ON i.equipement_id = e.id
        {where}""", params))

    today_iv = rows(db.execute(f"""
        SELECT i.numero, i.type, i.statut, e.designation, p.nom AS projet
        FROM interventions i
        JOIN equipements e ON i.equipement_id = e.id
        JOIN projets p     ON e.projet_id = p.id
        {where} AND DATE(i.date_prevue)=? AND i.statut NOT IN ('TERMINEE','ANNULEE')
        ORDER BY i.date_prevue""", params + [today()]))

    retards = rows(db.execute(f"""
        SELECT i.numero, i.type, i.date_prevue, e.designation, p.nom AS projet
        FROM interventions i
        JOIN equipements e ON i.equipement_id = e.id
        JOIN projets p     ON e.projet_id = p.id
        {where} AND i.date_prevue < ? AND i.statut NOT IN ('TERMINEE','ANNULEE')
        ORDER BY i.date_prevue""", params + [today()]))

    alertes = rows(db.execute("""
        SELECT p.type_piece, p.statut, p.date_fin_de_vie,
               e.designation AS equip_nom, pj.nom AS projet
        FROM pieces p
        JOIN equipements e ON p.equipement_id = e.id
        JOIN projets pj    ON e.projet_id = pj.id
        WHERE p.statut IN ('A_SURVEILLER','A_REMPLACER')
        ORDER BY p.date_fin_de_vie"""))

    equips = rows(db.execute("""
        SELECT e.id, e.designation, e.type_technique, p.nom AS projet
        FROM equipements e JOIN projets p ON e.projet_id = p.id"""))
    critiques = [e for e in equips if criticite_equipement(e["id"], db) == "CRITIQUE"]

    dep = rows(db.execute(f"""
        SELECT JULIANDAY(i.date_realisation)-JULIANDAY(i.date_creation) AS delta
        FROM interventions i JOIN equipements e ON i.equipement_id=e.id
        {where} AND i.type='DEPANNAGE' AND i.statut='TERMINEE'
          AND i.date_realisation IS NOT NULL""", params))
    mnt = rows(db.execute(f"""
        SELECT JULIANDAY(i.date_realisation)-JULIANDAY(i.date_prevue) AS delta
        FROM interventions i JOIN equipements e ON i.equipement_id=e.id
        {where} AND i.type='MAINTENANCE' AND i.statut='TERMINEE'
          AND i.date_realisation IS NOT NULL AND i.date_prevue IS NOT NULL""", params))

    moy_dep = round(sum(r["delta"] for r in dep if r["delta"]) / len(dep), 1) if dep else 0
    moy_mnt = round(sum(r["delta"] for r in mnt if r["delta"]) / len(mnt), 1) if mnt else 0

    return jsonify({
        "kpi": kpi, "today": today_iv, "retards": retards,
        "alertes": alertes, "critiques": critiques[:10],
        "stats": {
            "moy_jours_depannage":   moy_dep, "nb_depannages":   len(dep),
            "moy_jours_maintenance": moy_mnt, "nb_maintenances": len(mnt)
        }
    })

# ══════════════════════════════════════════════════════════
# API SMTP
# ══════════════════════════════════════════════════════════
@app.route("/api/smtp")
@require_auth
def get_smtp():
    r = one(get_db().execute(
        "SELECT host,port,username,use_tls,sender_email,sender_name,enabled FROM smtp_config WHERE id=1"))
    return jsonify(r or {})

@app.route("/api/smtp", methods=["POST"])
@require_role("admin")
def save_smtp():
    d = request.json or {}
    db = get_db()
    db.execute("""UPDATE smtp_config SET
        host=?,port=?,username=?,password=?,use_tls=?,
        sender_email=?,sender_name=?,enabled=? WHERE id=1""",
        (d.get("host",""), int(d.get("port",587)),
         d.get("username",""), d.get("password",""),
         1 if d.get("use_tls",True) else 0,
         d.get("sender_email",""), d.get("sender_name","SOCOM GMAO"),
         1 if d.get("enabled") else 0))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/smtp/test", methods=["POST"])
@require_role("admin")
def test_smtp():
    d  = request.json or {}
    to = d.get("to","")
    if not to: return jsonify({"error": "Email requis"}), 400
    ok = send_mail(to, "[GMAO] Test SMTP", "Test configuration SMTP — OK")
    return jsonify({"ok": ok})

# ══════════════════════════════════════════════════════════
# API EXPORT EXCEL
# ══════════════════════════════════════════════════════════
@app.route("/api/export/excel")
@require_auth
def export_excel():
    try:
        import openpyxl
        db = get_db()
        wb = openpyxl.Workbook()
        tables = {
            "Interventions":  "SELECT * FROM interventions",
            "Equipements":    "SELECT * FROM equipements",
            "Pieces":         "SELECT * FROM pieces",
            "Projets":        "SELECT * FROM projets",
            "Clients":        "SELECT * FROM clients",
            "Comptes_rendus": "SELECT id,intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,total_heures FROM comptes_rendus",
        }
        first = True
        for name, sql in tables.items():
            try:
                r = db.execute(sql).fetchall()
                if not r: continue
                ws = wb.active if first else wb.create_sheet(name)
                if first: ws.title = name; first = False
                ws.append([d[0] for d in db.execute(sql).description])
                for row in r: ws.append(list(row))
            except: continue
        buf = io.BytesIO(); wb.save(buf); buf.seek(0)
        return send_file(buf,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True, download_name="gmao_export.xlsx")
    except ImportError:
        return jsonify({"error": "openpyxl non installé"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════
# DÉMARRAGE
# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    import socket
    try:    ip = socket.gethostbyname(socket.gethostname())
    except: ip = "127.0.0.1"
    print("="*60)
    print("  SOCOM GMAO v2.0")
    print(f"  PC     : http://127.0.0.1:5000")
    print(f"  Mobile : http://127.0.0.1:5000/mobile")
    print(f"  Réseau : http://{ip}:5000")
    print(f"  DB     : {DB_PATH}")
    print("  Login  : admin@gmao.fr / admin")
    print("="*60)
    app.run(host="0.0.0.0", port=5000, debug=False)
