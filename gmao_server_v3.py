"""
SOCOM GMAO — Serveur v3
=======================
Version propre et complète.

DÉPLOIEMENT HOSTINGER VPS
--------------------------
1. Copier tous les fichiers dans /var/www/gmao/
2. cd /var/www/gmao && python3 -m venv venv
3. venv/bin/pip install flask flask-cors gunicorn openpyxl
4. Configurer systemd (voir DEPLOIEMENT.md)
5. systemctl start gmao

Variables d'environnement (optionnel) :
  GMAO_DB          : chemin vers la base SQLite
  GMAO_SYNC_SECRET : clé de synchronisation
"""

import hashlib, json, os, sqlite3, smtplib, io
from datetime import datetime
from functools import wraps
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from flask import Flask, jsonify, request, send_file, Response
    from flask_cors import CORS
except ImportError:
    raise ImportError("pip install flask flask-cors")

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

BASE_DIR    = Path(os.path.dirname(os.path.abspath(__file__)))
DB_PATH     = os.environ.get("GMAO_DB",          str(BASE_DIR / "gmao_shared.db"))
SYNC_SECRET = os.environ.get("GMAO_SYNC_SECRET", "SOCOM_GMAO_SYNC_2024")

app = Flask(__name__)
CORS(app, origins="*")

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS DB
# ══════════════════════════════════════════════════════════════════════════════

def get_db():
    if not os.path.exists(DB_PATH):
        raise RuntimeError(f"Base introuvable : {DB_PATH}")
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()
def now():      return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def today():    return datetime.now().strftime("%Y-%m-%d")
def rows(cur):  return [dict(r) for r in cur.fetchall()]
def row(cur):   r = cur.fetchone(); return dict(r) if r else None

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════════════════════

def check_auth(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): return None
    token = auth[7:]
    if ":" not in token: return None
    username, pw_hash = token.split(":", 1)
    try:
        db  = get_db()
        r   = db.execute(
            "SELECT username, full_name, role, lang, "
            "COALESCE(technique_access,'Toutes') AS technique_access "
            "FROM utilisateurs WHERE username=? AND password_hash=? AND is_active=1",
            (username, pw_hash)).fetchone()
        return dict(r) if r else None
    except Exception:
        return None

def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        user = check_auth(request)
        if not user: return jsonify({"error": "Non autorisé"}), 401
        request.user = user
        return fn(*a, **kw)
    return wrapper

def require_role(*roles):
    def dec(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = check_auth(request)
            if not user: return jsonify({"error": "Non autorisé"}), 401
            if user.get("role") not in roles:
                return jsonify({"error": "Accès interdit"}), 403
            request.user = user
            return fn(*a, **kw)
        return wrapper
    return dec

# ══════════════════════════════════════════════════════════════════════════════
#  MAIL
# ══════════════════════════════════════════════════════════════════════════════

def send_mail_bt(bt_id, action="création"):
    try:
        db  = get_db()
        cfg = db.execute("SELECT * FROM smtp_config WHERE id=1").fetchone()
        if not cfg or not cfg["enabled"]: return False

        bt = db.execute("""
            SELECT bt.numero_bt, bt.titre, bt.type_bt, bt.statut, bt.priorite,
                   bt.technicien_username, bt.description,
                   p.titre AS projet_titre, p.gestionnaire_username,
                   u.email AS gest_email, u.full_name AS gest_name
            FROM bons_travail bt
            LEFT JOIN projets p     ON bt.projet_id = p.id
            LEFT JOIN utilisateurs u ON p.gestionnaire_username = u.username
            WHERE bt.id = ?""", (bt_id,)).fetchone()

        if not bt or not bt["gest_email"]: return False

        subject = f"[GMAO] {action} — {bt['numero_bt']} {bt['titre']}"
        body = f"""Bonjour {bt['gest_name'] or bt['gestionnaire_username']},

Action : {action}

  Numéro     : {bt['numero_bt']}
  Titre      : {bt['titre']}
  Type       : {bt['type_bt']}
  Statut     : {bt['statut']}
  Priorité   : {bt['priorite']}
  Projet     : {bt['projet_titre'] or '—'}
  Technicien : {bt['technicien_username'] or '—'}
{chr(10)+'  Description : '+bt['description'] if bt['description'] else ''}

Cordialement,
SOCOM GMAO"""

        msg = MIMEMultipart()
        msg["From"]    = f"{cfg['sender_name']} <{cfg['sender_email']}>"
        msg["To"]      = bt["gest_email"]
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as srv:
            if cfg["use_tls"]: srv.starttls()
            if cfg["username"]: srv.login(cfg["username"], cfg["password"])
            srv.sendmail(cfg["sender_email"], bt["gest_email"], msg.as_string())
        return True
    except Exception as e:
        print(f"[MAIL] {e}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  PLANNING AUTO
# ══════════════════════════════════════════════════════════════════════════════

def auto_planning(bt_id, db):
    try:
        bt    = db.execute("SELECT * FROM bons_travail WHERE id=?", (bt_id,)).fetchone()
        if not bt: return
        count = db.execute("SELECT COUNT(*) FROM planning").fetchone()[0] + 1
        db.execute("""
            INSERT INTO planning
            (numero_pl, equipement_id, projet_id, technicien_username,
             date_prevue, heure_prevue, type_intervention, statut, notes,
             created_by, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (f"PL{count:05d}",
             bt["equipement_id"], bt["projet_id"],
             bt["technicien_username"],
             bt["date_prevue"] or today(),
             bt["heure_prevue"] or "",
             bt["type_bt"] or "Maintenance",
             "Planifié",
             f"Auto — {bt['numero_bt']} {bt['titre']}",
             bt["created_by"] or "system",
             now(), now()))
        db.commit()
    except Exception as e:
        print(f"[PLANNING AUTO] {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  FRONTEND
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@app.route("/mobile")
def index():
    f = BASE_DIR / "gmao_mobile_v2.html"
    if f.exists(): return send_file(str(f))
    return "<h1>gmao_mobile_v2.html introuvable</h1>", 404

@app.route("/pc")
def pc():
    f = BASE_DIR / "gmao_web_pc.html"
    if f.exists(): return send_file(str(f))
    return "<h1>gmao_web_pc.html introuvable</h1>", 404

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
        "name": "SOCOM GMAO", "short_name": "GMAO",
        "start_url": "/", "display": "standalone",
        "background_color": "#1f2b35", "theme_color": "#2563eb",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
        ]
    })

@app.route("/health")
def health():
    try:
        db = get_db(); db.execute("SELECT 1")
        return jsonify({"status": "ok", "time": now()})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  API — AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    u = (d.get("username") or "").strip()
    p = (d.get("password") or "").strip()
    if not u or not p: return jsonify({"error": "Identifiants manquants"}), 400
    try:
        db  = get_db()
        r   = db.execute(
            "SELECT username, full_name, role, lang, "
            "COALESCE(technique_access,'Toutes') AS technique_access "
            "FROM utilisateurs WHERE username=? AND password_hash=? AND is_active=1",
            (u, hash_pw(p))).fetchone()
        if not r: return jsonify({"error": "Identifiants incorrects"}), 401
        user = dict(r)
        user["token"] = f"{u}:{hash_pw(p)}"
        return jsonify(user)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  API — BONS DE TRAVAIL
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/bons_travail", methods=["GET"])
@require_auth
def get_bts():
    user = request.user
    db   = get_db()
    sql  = """
        SELECT bt.id, bt.numero_bt, bt.titre, bt.type_bt, bt.priorite, bt.statut,
               bt.date_ouverture, bt.date_prevue, bt.date_cloture, bt.heure_prevue,
               bt.technicien_username, bt.description, bt.notes,
               COALESCE(e.nom,'') AS equipement,
               COALESCE(p.titre,'') AS projet,
               bt.equipement_id, bt.projet_id
        FROM bons_travail bt
        LEFT JOIN equipements e ON bt.equipement_id = e.id
        LEFT JOIN projets p     ON bt.projet_id = p.id
        WHERE 1=1"""
    params = []
    if user["role"] == "technicien":
        sql += " AND bt.technicien_username=?"; params.append(user["username"])
    if request.args.get("statut"):
        sql += " AND bt.statut=?"; params.append(request.args["statut"])
    if request.args.get("type"):
        sql += " AND bt.type_bt=?"; params.append(request.args["type"])
    sql += " ORDER BY bt.date_ouverture DESC LIMIT 500"
    return jsonify(rows(db.execute(sql, params)))

@app.route("/api/bons_travail/<int:bt_id>", methods=["GET"])
@require_auth
def get_bt(bt_id):
    db = get_db()
    r  = db.execute("""
        SELECT bt.*, COALESCE(e.nom,'') AS equipement, COALESCE(p.titre,'') AS projet
        FROM bons_travail bt
        LEFT JOIN equipements e ON bt.equipement_id = e.id
        LEFT JOIN projets p     ON bt.projet_id = p.id
        WHERE bt.id=?""", (bt_id,)).fetchone()
    if not r: return jsonify({"error": "Non trouvé"}), 404
    return jsonify(dict(r))

@app.route("/api/bons_travail", methods=["POST"])
@require_auth
def create_bt():
    user  = request.user
    d     = request.json or {}
    titre = (d.get("titre") or "").strip()
    if not titre: return jsonify({"error": "Titre requis"}), 400
    db    = get_db()
    count = db.execute("SELECT COUNT(*) FROM bons_travail").fetchone()[0] + 1
    num   = f"BT{count:05d}"
    db.execute("""
        INSERT INTO bons_travail
        (numero_bt, type_bt, titre, description, priorite, statut,
         technicien_username, date_ouverture, date_prevue, heure_prevue,
         equipement_id, projet_id, notes, created_by, updated_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (num, d.get("type_bt","Maintenance"), titre,
         d.get("description",""), d.get("priorite","Normale"), "Ouvert",
         d.get("technicien_username", user["username"]),
         today(), d.get("date_prevue",""), d.get("heure_prevue",""),
         d.get("equipement_id") or None, d.get("projet_id") or None,
         d.get("notes",""), user["username"], user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    auto_planning(new_id, db)
    try: send_mail_bt(new_id, "Création BT")
    except: pass
    return jsonify({"id": new_id, "numero_bt": num}), 201

@app.route("/api/bons_travail/<int:bt_id>", methods=["PATCH"])
@require_auth
def update_bt(bt_id):
    user = request.user
    d    = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["statut","priorite","notes","date_prevue","heure_prevue",
              "technicien_username","description","titre","type_bt","date_cloture"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if "statut" in d and d["statut"] == "Terminé":
        sets.append("date_cloture=?"); params.append(today())
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_by=?","updated_at=?"]
    params += [user["username"], now(), bt_id]
    db.execute(f"UPDATE bons_travail SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    if "statut" in d:
        try: send_mail_bt(bt_id, f"Statut → {d['statut']}")
        except: pass
    return jsonify({"ok": True})

@app.route("/api/bons_travail/<int:bt_id>", methods=["DELETE"])
@require_role("admin")
def delete_bt(bt_id):
    db = get_db()
    db.execute("DELETE FROM bons_travail WHERE id=?", (bt_id,))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/bons_travail/<int:bt_id>/comptes_rendus", methods=["GET"])
@require_auth
def get_cr_by_bt(bt_id):
    db = get_db()
    return jsonify(rows(db.execute("""
        SELECT id, numero_cr, date_intervention, heure_debut, heure_fin,
               intervenants, remarques, statut, total_heures
        FROM comptes_rendus WHERE bon_travail_id=?
        ORDER BY date_intervention DESC""", (bt_id,))))

# ══════════════════════════════════════════════════════════════════════════════
#  API — PLANNING
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/planning", methods=["GET"])
@require_auth
def get_planning():
    user = request.user
    db   = get_db()
    sql  = """
        SELECT pl.id, pl.numero_pl, pl.statut, pl.date_prevue, pl.heure_prevue, pl.heure_fin,
               pl.type_intervention, pl.technicien_username, pl.notes,
               COALESCE(e.nom,'') AS equipement, COALESCE(p.titre,'') AS projet
        FROM planning pl
        LEFT JOIN equipements e ON pl.equipement_id = e.id
        LEFT JOIN projets p     ON pl.projet_id = p.id
        WHERE 1=1"""
    params = []
    if user["role"] == "technicien":
        sql += " AND pl.technicien_username=?"; params.append(user["username"])
    if request.args.get("from"):
        sql += " AND pl.date_prevue >= ?"; params.append(request.args["from"])
    if request.args.get("to"):
        sql += " AND pl.date_prevue <= ?"; params.append(request.args["to"])
    sql += " ORDER BY pl.date_prevue ASC, pl.heure_prevue ASC LIMIT 500"
    return jsonify(rows(db.execute(sql, params)))

@app.route("/api/planning/<int:pl_id>", methods=["PATCH"])
@require_auth
def update_planning(pl_id):
    user = request.user
    d    = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["statut","notes","date_realisation","heure_fin","date_prevue","heure_prevue"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_by=?","updated_at=?"]
    params += [user["username"], now(), pl_id]
    db.execute(f"UPDATE planning SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  API — COMPTES RENDUS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/comptes_rendus", methods=["GET"])
@require_auth
def get_crs():
    user = request.user
    db   = get_db()
    sql  = """
        SELECT cr.id, cr.numero_cr, cr.date_intervention, cr.heure_debut, cr.heure_fin,
               cr.remarques, cr.statut, cr.total_heures, cr.intervenants,
               bt.titre AS bt_titre, bt.numero_bt,
               COALESCE(e.nom,'') AS equipement
        FROM comptes_rendus cr
        JOIN bons_travail bt    ON cr.bon_travail_id = bt.id
        LEFT JOIN equipements e ON bt.equipement_id = e.id
        WHERE 1=1"""
    params = []
    if user["role"] == "technicien":
        sql += " AND bt.technicien_username=?"; params.append(user["username"])
    sql += " ORDER BY cr.date_intervention DESC LIMIT 200"
    return jsonify(rows(db.execute(sql, params)))

@app.route("/api/comptes_rendus", methods=["POST"])
@require_auth
def create_cr():
    user  = request.user
    d     = request.json or {}
    bt_id = d.get("bon_travail_id")
    if not bt_id: return jsonify({"error": "bon_travail_id requis"}), 400
    db    = get_db()
    count = db.execute("SELECT COUNT(*) FROM comptes_rendus").fetchone()[0] + 1
    num   = f"CR{count:05d}"
    db.execute("""
        INSERT INTO comptes_rendus
        (numero_cr, bon_travail_id, date_intervention, heure_debut, heure_fin,
         intervenants, remarques, statut, total_heures, created_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (num, int(bt_id),
         d.get("date_intervention", today()),
         d.get("heure_debut",""), d.get("heure_fin",""),
         json.dumps(d.get("intervenants",[])),
         d.get("remarques",""), d.get("statut","En cours"),
         d.get("total_heures",""),
         user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id, "numero_cr": num}), 201

@app.route("/api/comptes_rendus/<int:cr_id>", methods=["PATCH"])
@require_auth
def update_cr(cr_id):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["date_intervention","heure_debut","heure_fin","remarques","statut","total_heures"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if "intervenants" in d:
        sets.append("intervenants=?"); params.append(json.dumps(d["intervenants"]))
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_at=?"]; params += [now(), cr_id]
    db.execute(f"UPDATE comptes_rendus SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  API — ÉQUIPEMENTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/equipements", methods=["GET"])
@require_auth
def get_equipements():
    db = get_db()
    sql = """
        SELECT e.*, COALESCE(p.titre,'') AS projet_titre,
               COALESCE(c.societe, c.nom,'') AS client_nom
        FROM equipements e
        LEFT JOIN projets p  ON e.projet_id = p.id
        LEFT JOIN clients c  ON e.client_id = c.id
        WHERE COALESCE(e.statut,'') != 'Résilié'
        ORDER BY LOWER(e.nom) LIMIT 500"""
    q = request.args.get("q","")
    if q:
        sql = sql.replace("WHERE", f"WHERE (e.nom LIKE '%{q}%' OR COALESCE(p.titre,'') LIKE '%{q}%') AND")
    return jsonify(rows(db.execute(sql)))

@app.route("/api/equipements", methods=["POST"])
@require_auth
def create_equipement():
    user = request.user
    d    = request.json or {}
    nom  = (d.get("nom") or "").strip()
    if not nom: return jsonify({"error": "Nom requis"}), 400
    db   = get_db()
    # Récupérer le client_id depuis le projet
    client_id = d.get("client_id") or None
    if d.get("projet_id") and not client_id:
        pj = db.execute("SELECT client_id FROM projets WHERE id=?", (d["projet_id"],)).fetchone()
        if pj: client_id = pj["client_id"]
    db.execute("""
        INSERT INTO equipements
        (nom, designation, marque, type_eq, numero_serie, statut,
         projet_id, client_id, notes, created_by, updated_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (nom, d.get("designation",""), d.get("marque",""),
         d.get("type_eq",""), d.get("numero_serie",""),
         d.get("statut","En contrat"),
         d.get("projet_id") or None, client_id,
         d.get("notes",""),
         user["username"], user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id}), 201

@app.route("/api/equipements/<int:eq_id>", methods=["PATCH"])
@require_auth
def update_equipement(eq_id):
    user = request.user
    d    = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["nom","designation","marque","type_eq","numero_serie","statut",
              "projet_id","client_id","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f] or None if f in ["projet_id","client_id"] else d[f])
    if "projet_id" in d and d["projet_id"] and "client_id" not in d:
        pj = db.execute("SELECT client_id FROM projets WHERE id=?", (d["projet_id"],)).fetchone()
        if pj: sets.append("client_id=?"); params.append(pj["client_id"])
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_by=?","updated_at=?"]
    params += [user["username"], now(), eq_id]
    db.execute(f"UPDATE equipements SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  API — CLIENTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/clients", methods=["GET"])
@require_auth
def get_clients():
    db = get_db()
    return jsonify(rows(db.execute(
        "SELECT * FROM clients ORDER BY COALESCE(societe,nom) LIMIT 500")))

@app.route("/api/clients", methods=["POST"])
@require_auth
def create_client():
    d   = request.json or {}
    nom = (d.get("nom") or "").strip()
    if not nom: return jsonify({"error": "Nom requis"}), 400
    db  = get_db()
    db.execute("""INSERT INTO clients (nom,societe,prenom,email,telephone,notes,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (nom, d.get("societe",""), d.get("prenom",""),
         d.get("email",""), d.get("telephone",""),
         d.get("notes",""), now(), now()))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201

@app.route("/api/clients/<int:cl_id>", methods=["PATCH"])
@require_auth
def update_client(cl_id):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["nom","societe","prenom","email","telephone","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error": "Rien"}), 400
    sets += ["updated_at=?"]; params += [now(), cl_id]
    db.execute(f"UPDATE clients SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  API — PROJETS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/projets", methods=["GET"])
@require_auth
def get_projets():
    db = get_db()
    return jsonify(rows(db.execute("""
        SELECT p.*, COALESCE(c.societe, c.nom,'') AS client_nom
        FROM projets p LEFT JOIN clients c ON p.client_id = c.id
        ORDER BY LOWER(p.titre) LIMIT 500""")))

@app.route("/api/projets", methods=["POST"])
@require_auth
def create_projet():
    user  = request.user
    d     = request.json or {}
    titre = (d.get("titre") or "").strip()
    if not titre: return jsonify({"error": "Titre requis"}), 400
    db    = get_db()
    db.execute("""INSERT INTO projets
        (titre,numero_projet,client_id,gestionnaire_username,description,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (titre, d.get("numero_projet",""),
         d.get("client_id") or None,
         d.get("gestionnaire_username") or None,
         d.get("description",""),
         user["username"], now(), now()))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201

@app.route("/api/projets/<int:pj_id>", methods=["PATCH"])
@require_auth
def update_projet(pj_id):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["titre","numero_projet","client_id","gestionnaire_username","description"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f] or None if f in ["client_id","gestionnaire_username"] else d[f])
    if not sets: return jsonify({"error": "Rien"}), 400
    sets += ["updated_at=?"]; params += [now(), pj_id]
    db.execute(f"UPDATE projets SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  API — GAMMES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/gammes", methods=["GET"])
@require_auth
def get_gammes():
    db = get_db()
    try:
        return jsonify(rows(db.execute("""
            SELECT id, titre, domaine AS technique, periodicite, duree_estimee, description
            FROM gammes ORDER BY LOWER(titre) LIMIT 200""")))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/gammes", methods=["POST"])
@require_auth
def create_gamme():
    user  = request.user
    d     = request.json or {}
    titre = (d.get("titre") or "").strip()
    if not titre: return jsonify({"error": "Titre requis"}), 400
    db    = get_db()
    db.execute("""INSERT INTO gammes
        (titre,domaine,periodicite,duree_estimee,description,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (titre, d.get("technique","") or d.get("domaine",""),
         d.get("periodicite",""), d.get("duree_estimee",""),
         d.get("description",""), user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id}), 201

@app.route("/api/gammes/<int:g_id>", methods=["PATCH"])
@require_auth
def update_gamme(g_id):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f, col in [("titre","titre"),("technique","domaine"),("periodicite","periodicite"),
                   ("duree_estimee","duree_estimee"),("description","description")]:
        if f in d: sets.append(f"{col}=?"); params.append(d[f])
    if not sets: return jsonify({"error": "Rien"}), 400
    sets += ["updated_at=?"]; params += [now(), g_id]
    db.execute(f"UPDATE gammes SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/gammes/<int:g_id>/operations", methods=["GET"])
@require_auth
def get_operations(g_id):
    db = get_db()
    try:
        return jsonify(rows(db.execute(
            "SELECT * FROM operations_gamme WHERE gamme_id=? ORDER BY ordre", (g_id,))))
    except: return jsonify([])

@app.route("/api/gammes/<int:g_id>/operations", methods=["POST"])
@require_auth
def create_operation(g_id):
    d = request.json or {}
    titre = (d.get("titre") or "").strip()
    if not titre: return jsonify({"error": "Titre requis"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO operations_gamme (gamme_id,ordre,titre,description) VALUES (?,?,?,?)",
            (g_id, d.get("ordre",0), titre, d.get("description","")))
        db.commit()
        return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  API — RÉFÉRENCE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/techniciens", methods=["GET"])
@require_auth
def get_techniciens():
    db = get_db()
    return jsonify(rows(db.execute(
        "SELECT username, full_name, role FROM utilisateurs "
        "WHERE role IN ('technicien','admin','gestionnaire') AND is_active=1 ORDER BY full_name")))

@app.route("/api/equipements/par_projet/<int:projet_id>", methods=["GET"])
@require_auth
def get_equip_par_projet(projet_id):
    db = get_db()
    return jsonify(rows(db.execute(
        "SELECT id, nom FROM equipements WHERE projet_id=? ORDER BY LOWER(nom)", (projet_id,))))

# ══════════════════════════════════════════════════════════════════════════════
#  API — UTILISATEURS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/utilisateurs", methods=["GET"])
@require_auth
def get_utilisateurs():
    db = get_db()
    return jsonify(rows(db.execute(
        "SELECT id,username,full_name,email,role,lang,is_active,technique_access "
        "FROM utilisateurs ORDER BY full_name")))

@app.route("/api/utilisateurs", methods=["POST"])
@require_role("admin","gestionnaire")
def create_utilisateur():
    d = request.json or {}
    u = (d.get("username") or "").strip()
    p = (d.get("password") or "").strip()
    if not u or not p: return jsonify({"error": "Identifiant et mot de passe requis"}), 400
    db = get_db()
    try:
        db.execute("""INSERT INTO utilisateurs
            (username,password_hash,full_name,email,role,lang,is_active,created_at)
            VALUES (?,?,?,?,?,?,1,?)""",
            (u, hash_pw(p), d.get("full_name",""), d.get("email",""),
             d.get("role","technicien"), d.get("lang","fr"), now()))
        db.commit()
        return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/utilisateurs/<int:u_id>", methods=["PATCH"])
@require_role("admin","gestionnaire")
def update_utilisateur(u_id):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["full_name","email","role","lang","is_active","technique_access"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if "password" in d and d["password"]:
        sets.append("password_hash=?"); params.append(hash_pw(d["password"]))
    if not sets: return jsonify({"error": "Rien"}), 400
    params.append(u_id)
    db.execute(f"UPDATE utilisateurs SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  API — ÉQUIPES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/equipes", methods=["GET"])
@require_auth
def get_equipes():
    db = get_db()
    try:
        return jsonify(rows(db.execute("SELECT * FROM equipes ORDER BY nom")))
    except: return jsonify([])

@app.route("/api/equipes", methods=["POST"])
@require_auth
def create_equipe():
    d   = request.json or {}
    nom = (d.get("nom") or "").strip()
    if not nom: return jsonify({"error": "Nom requis"}), 400
    db  = get_db()
    db.execute("INSERT INTO equipes (nom,description,gestionnaire_username,created_at,updated_at) VALUES (?,?,?,?,?)",
        (nom, d.get("description",""), d.get("gestionnaire_username") or None, now(), now()))
    db.commit()
    return jsonify({"id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}), 201

@app.route("/api/equipes/<int:eq_id>", methods=["PATCH"])
@require_auth
def update_equipe(eq_id):
    d = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["nom","description","gestionnaire_username"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f] or None)
    if not sets: return jsonify({"error": "Rien"}), 400
    sets += ["updated_at=?"]; params += [now(), eq_id]
    db.execute(f"UPDATE equipes SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/equipes/<int:eq_id>/membres", methods=["GET"])
@require_auth
def get_membres(eq_id):
    db = get_db()
    try:
        return jsonify(rows(db.execute("""
            SELECT et.technicien_username,
                   COALESCE(u.full_name, et.technicien_username) AS full_name
            FROM equipe_techniciens et
            LEFT JOIN utilisateurs u ON et.technicien_username = u.username
            WHERE et.equipe_id=?""", (eq_id,))))
    except: return jsonify([])

@app.route("/api/equipes/<int:eq_id>/membres", methods=["POST"])
@require_auth
def add_membre(eq_id):
    d = request.json or {}
    t = (d.get("technicien_username") or "").strip()
    if not t: return jsonify({"error": "technicien_username requis"}), 400
    db = get_db()
    try:
        db.execute("INSERT OR IGNORE INTO equipe_techniciens (equipe_id,technicien_username) VALUES (?,?)", (eq_id, t))
        db.commit()
        return jsonify({"ok": True}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/equipes/<int:eq_id>/membres/<username>", methods=["DELETE"])
@require_auth
def remove_membre(eq_id, username):
    db = get_db()
    db.execute("DELETE FROM equipe_techniciens WHERE equipe_id=? AND technicien_username=?", (eq_id, username))
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  API — TECHNIQUE
# ══════════════════════════════════════════════════════════════════════════════

TECH_PREFIXES = ["ups","ht","ge","es","di","des"]
TECH_ACCESS   = {
    "ups": "UPS", "ht": "Haute tension", "ge": "Groupe électrogène",
    "es": "Eclairage de secours", "di": "Détection incendie", "des": "Désenfumage"
}

def check_tech_access(user, prefix):
    access = user.get("technique_access","Toutes")
    return access == "Toutes" or TECH_ACCESS.get(prefix) == access

@app.route("/api/technique/<prefix>", methods=["GET"])
@require_auth
def get_technique(prefix):
    if prefix not in TECH_PREFIXES: return jsonify({"error": "Préfixe invalide"}), 400
    if not check_tech_access(request.user, prefix): return jsonify({"error": "Accès interdit"}), 403
    db     = get_db()
    search = request.args.get("search","")
    try:
        sql = f"""
            SELECT u.id, u.designation_ups AS designation, u.marque, u.type_ups AS type,
                   u.puissance, u.in_out, u.numero_serie AS serie, u.mise_en_service AS mes,
                   COALESCE(u.nombre_string_dc,'') AS string_dc,
                   COALESCE(pj.titre,'—') AS projet
            FROM {prefix}_installations u
            LEFT JOIN equipements e ON u.idmat_id = e.id
            LEFT JOIN projets pj    ON e.client_id = pj.id
            WHERE 1=1"""
        params = []
        if search:
            sql += " AND (u.designation_ups LIKE ? OR u.numero_serie LIKE ? OR pj.titre LIKE ?)"
            params += [f"%{search}%"]*3
        sql += " ORDER BY pj.titre, u.designation_ups LIMIT 300"
        return jsonify(rows(db.execute(sql, params)))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/technique/<prefix>/<int:inst_id>", methods=["PATCH"])
@require_auth
def update_technique(prefix, inst_id):
    if prefix not in TECH_PREFIXES: return jsonify({"error": "Préfixe invalide"}), 400
    d  = request.json or {}
    db = get_db()
    sets, params = [], []
    for f in ["designation_ups","marque","type_ups","puissance","numero_serie",
              "mise_en_service","in_out","nombre_string_dc"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error": "Rien"}), 400
    params.append(inst_id)
    try:
        db.execute(f"UPDATE {prefix}_installations SET {', '.join(sets)} WHERE id=?", params)
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/technique/<prefix>/pieces", methods=["GET"])
@require_auth
def get_pieces(prefix):
    if prefix not in TECH_PREFIXES: return jsonify({"error": "Préfixe invalide"}), 400
    db = get_db()
    try:
        return jsonify(rows(db.execute(f"""
            SELECT p.*, u.designation_ups AS designation
            FROM {prefix}_pieces p
            LEFT JOIN {prefix}_installations u ON p.installation_id = u.id
            ORDER BY u.designation_ups, p.type_piece LIMIT 300""")))
    except: return jsonify([])

# ══════════════════════════════════════════════════════════════════════════════
#  API — SMTP
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/smtp", methods=["GET"])
@require_auth
def get_smtp():
    db  = get_db()
    r   = db.execute(
        "SELECT host,port,username,use_tls,sender_email,sender_name,enabled FROM smtp_config WHERE id=1"
    ).fetchone()
    return jsonify(dict(r) if r else {})

@app.route("/api/smtp", methods=["POST"])
@require_role("admin")
def save_smtp():
    d  = request.json or {}
    db = get_db()
    db.execute("""UPDATE smtp_config SET
        host=?,port=?,username=?,password=?,use_tls=?,
        sender_email=?,sender_name=?,enabled=?,updated_at=?
        WHERE id=1""",
        (d.get("host",""), int(d.get("port",587)),
         d.get("username",""), d.get("password",""),
         1 if d.get("use_tls",True) else 0,
         d.get("sender_email",""), d.get("sender_name","SOCOM GMAO"),
         1 if d.get("enabled",False) else 0, now()))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/smtp/test", methods=["POST"])
@require_role("admin")
def test_smtp():
    d  = request.json or {}
    to = d.get("to","")
    if not to: return jsonify({"error": "Email requis"}), 400
    try:
        db  = get_db()
        cfg = db.execute("SELECT * FROM smtp_config WHERE id=1").fetchone()
        if not cfg: return jsonify({"error": "SMTP non configuré"}), 400
        msg = MIMEText("Test SMTP SOCOM GMAO — OK", "plain", "utf-8")
        msg["From"]    = f"{cfg['sender_name']} <{cfg['sender_email']}>"
        msg["To"]      = to
        msg["Subject"] = "[GMAO] Test SMTP"
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as srv:
            if cfg["use_tls"]: srv.starttls()
            if cfg["username"]: srv.login(cfg["username"], cfg["password"])
            srv.sendmail(cfg["sender_email"], to, msg.as_string())
        return jsonify({"ok": True, "message": "Email envoyé"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  API — EXPORT / IMPORT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/export/excel", methods=["GET"])
@require_auth
def export_excel():
    try:
        import openpyxl
        db  = get_db()
        wb  = openpyxl.Workbook()
        tbl = {
            "Bons de travail":   "SELECT * FROM bons_travail",
            "Planning":          "SELECT * FROM planning",
            "Comptes rendus":    "SELECT * FROM comptes_rendus",
            "Equipements":       "SELECT * FROM equipements",
            "Clients":           "SELECT * FROM clients",
            "Projets":           "SELECT * FROM projets",
            "Gammes":            "SELECT * FROM gammes",
            "Utilisateurs":      "SELECT id,username,full_name,email,role,lang,is_active FROM utilisateurs",
            "Equipes":           "SELECT * FROM equipes",
        }
        first = True
        for name, sql in tbl.items():
            try:
                r = db.execute(sql).fetchall()
                if not r: continue
                ws = wb.active if first else wb.create_sheet(name)
                if first: ws.title = name; first = False
                ws.append([d[0] for d in db.execute(sql).description])
                for row_ in r: ws.append(list(row_))
            except: continue
        buf = io.BytesIO()
        wb.save(buf); buf.seek(0)
        return send_file(buf,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True, download_name="gmao_export.xlsx")
    except ImportError:
        return jsonify({"error": "openpyxl non installé"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  API — SYNCHRONISATION PC→CLOUD
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/sync", methods=["POST"])
def sync_from_pc():
    if request.headers.get("X-Sync-Secret","") != SYNC_SECRET:
        return jsonify({"error": "Clé invalide"}), 403
    payload = request.json or {}
    tables  = payload.get("tables", {})
    if not tables: return jsonify({"error": "Aucune donnée"}), 400
    db = get_db(); total = 0; errors = []
    for table, rows_ in tables.items():
        if not rows_: continue
        try:
            cols = list(rows_[0].keys())
            ph   = ", ".join(["?"]*len(cols))
            cs   = ", ".join(cols)
            for r in rows_:
                try:
                    db.execute(f"INSERT OR REPLACE INTO {table} ({cs}) VALUES ({ph})",
                               [r.get(c) for c in cols])
                    total += 1
                except Exception as e:
                    errors.append(f"{table}: {e}")
        except Exception as e:
            errors.append(f"{table}: {e}")
    db.commit()
    return jsonify({"ok": True, "rows_synced": total, "errors": errors[:10]})

@app.route("/api/sync/status", methods=["GET"])
def sync_status():
    if request.headers.get("X-Sync-Secret","") != SYNC_SECRET:
        return jsonify({"error": "Clé invalide"}), 403
    try:
        db = get_db()
        return jsonify({
            "status":       "ok",
            "bons_travail": db.execute("SELECT COUNT(*) FROM bons_travail").fetchone()[0],
            "planning":     db.execute("SELECT COUNT(*) FROM planning").fetchone()[0],
            "utilisateurs": db.execute("SELECT COUNT(*) FROM utilisateurs").fetchone()[0],
            "server_time":  now()
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  DÉMARRAGE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import socket
    try:    ip = socket.gethostbyname(socket.gethostname())
    except: ip = "127.0.0.1"
    print("=" * 60)
    print("  SOCOM GMAO v3")
    print(f"  PC     : http://127.0.0.1:5000/pc")
    print(f"  Mobile : http://127.0.0.1:5000/")
    print(f"  Réseau : http://{ip}:5000")
    print(f"  DB     : {DB_PATH}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
