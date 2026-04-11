"""
SOCOM GMAO — Serveur API v2
Sert à la fois la version PC Web et la version Mobile PWA.
Compatible PythonAnywhere + VPS (gunicorn / waitress).

STRUCTURE DES FICHIERS SUR LE SERVEUR :
  /home/[user]/gmao/
    ├── gmao_server_v2.py      ← ce fichier
    ├── gmao_web_pc.html       ← interface PC
    ├── gmao_mobile_v2.html    ← interface Mobile PWA
    ├── sw.js                  ← Service Worker
    ├── manifest.json          ← manifest PWA (généré dynamiquement)
    └── gmao_shared.db         ← base de données SQLite

DÉPLOIEMENT PYTHONANYWHERE :
  1. Uploader tous les fichiers dans /home/[username]/gmao/
  2. Console Bash :
       pip3 install --user flask flask-cors
  3. Onglet Web > Add new web app > Manual config > Python 3.10
     WSGI file :
       import sys
       sys.path.insert(0, '/home/[username]/gmao')
       from gmao_server_v2 import app as application
  4. Static files : URL=/static/  Path=/home/[username]/gmao/static/
  5. Reload

DÉPLOIEMENT VPS (recommandé) :
  pip install flask flask-cors gunicorn
  gunicorn -w 2 -b 0.0.0.0:8000 gmao_server_v2:app
  → Utiliser nginx en reverse proxy
"""

import hashlib, json, os, sqlite3
from datetime import datetime
from pathlib import Path
from functools import wraps

try:
    from flask import Flask, jsonify, request, send_file, Response
    from flask_cors import CORS
except ImportError:
    raise ImportError("pip install flask flask-cors")

# ── Configuration ──────────────────────────────────────────────────────────────
BASE_DIR    = Path(os.path.dirname(os.path.abspath(__file__)))
DB_PATH     = os.environ.get("GMAO_DB",     str(BASE_DIR / "gmao_shared.db"))
SYNC_SECRET = os.environ.get("GMAO_SYNC_SECRET", "SOCOM_GMAO_SYNC_2024")

# ── App Flask ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=str(BASE_DIR / "static"))
CORS(app, origins="*")

# ── Helpers ───────────────────────────────────────────────────────────────────
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

# ── Auth ──────────────────────────────────────────────────────────────────────
def check_auth(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): return None
    token = auth[7:]
    if ":" not in token: return None
    username, pw_hash = token.split(":", 1)
    try:
        db  = get_db()
        row = db.execute(
            "SELECT username, full_name, role, lang, "
            "COALESCE(technique_access,'Toutes') AS technique_access "
            "FROM utilisateurs WHERE username=? AND password_hash=? AND is_active=1",
            (username, pw_hash)).fetchone()
        return dict(row) if row else None
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
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = check_auth(request)
            if not user: return jsonify({"error": "Non autorisé"}), 401
            if user.get("role") not in roles:
                return jsonify({"error": "Accès interdit"}), 403
            request.user = user
            return fn(*a, **kw)
        return wrapper
    return decorator

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES FRONTEND — Servir les fichiers HTML
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@app.route("/mobile")
def index():
    """Route principale — détecte mobile ou PC via User-Agent, ou via paramètre ?v="""
    v = request.args.get("v", "")
    ua = request.headers.get("User-Agent", "").lower()
    is_mobile = any(x in ua for x in ["mobile", "android", "iphone", "ipad"])

    if v == "pc" or (not is_mobile and v != "mobile"):
        pc_html = BASE_DIR / "gmao_web_pc.html"
        if pc_html.exists(): return send_file(str(pc_html))
        return "<h1>gmao_web_pc.html introuvable</h1>", 404
    else:
        mob_html = BASE_DIR / "gmao_mobile_v2.html"
        if mob_html.exists(): return send_file(str(mob_html))
        # Fallback ancienne version
        mob_old = BASE_DIR / "gmao_mobile.html"
        if mob_old.exists(): return send_file(str(mob_old))
        return "<h1>gmao_mobile_v2.html introuvable</h1>", 404

@app.route("/pc")
def pc_interface():
    """Forcer l'interface PC."""
    pc_html = BASE_DIR / "gmao_web_pc.html"
    if pc_html.exists(): return send_file(str(pc_html))
    return "<h1>gmao_web_pc.html introuvable</h1>", 404

@app.route("/sw.js")
def service_worker():
    """Service Worker pour la PWA mobile."""
    sw_path = BASE_DIR / "sw.js"
    if sw_path.exists():
        return Response(
            sw_path.read_text(encoding="utf-8"),
            mimetype="application/javascript",
            headers={"Service-Worker-Allowed": "/"}
        )
    return "// SW not found", 404

@app.route("/manifest.json")
def manifest():
    """Manifest PWA."""
    return jsonify({
        "name":             "SOCOM GMAO",
        "short_name":       "GMAO",
        "description":      "Gestion de Maintenance Assistée par Ordinateur",
        "start_url":        "/",
        "display":          "standalone",
        "orientation":      "portrait",
        "background_color": "#1f2b35",
        "theme_color":      "#2563eb",
        "lang":             "fr",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        ],
        "shortcuts": [
            {"name": "Bons de travail", "url": "/?section=bons_travail", "description": "Voir les BT"},
            {"name": "Planning",        "url": "/?section=planning",     "description": "Voir le planning"},
        ]
    })

@app.route("/health")
def health():
    try:
        db = get_db()
        db.execute("SELECT 1")
        return jsonify({"status": "ok", "db": "ok", "time": now()})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH API
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Identifiants manquants"}), 400
    try:
        db  = get_db()
        row = db.execute(
            "SELECT username, full_name, role, lang, "
            "COALESCE(technique_access,'Toutes') AS technique_access "
            "FROM utilisateurs WHERE username=? AND password_hash=? AND is_active=1",
            (username, hash_pw(password))).fetchone()
        if not row: return jsonify({"error": "Identifiants incorrects"}), 401
        user = dict(row)
        user["token"] = f"{username}:{hash_pw(password)}"
        return jsonify(user)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/me")
@require_auth
def me():
    return jsonify(request.user)

# ══════════════════════════════════════════════════════════════════════════════
#  BONS DE TRAVAIL
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/bons_travail", methods=["GET"])
@require_auth
def get_bons_travail():
    user   = request.user
    db     = get_db()
    sql    = """
        SELECT bt.id, bt.numero_bt, bt.titre, bt.type_bt, bt.priorite, bt.statut,
               bt.date_ouverture, bt.date_prevue, bt.heure_prevue,
               bt.technicien_username, bt.description, bt.notes,
               COALESCE(e.nom,'') AS equipement,
               COALESCE(p.titre,'') AS projet
        FROM bons_travail bt
        LEFT JOIN equipements e ON bt.equipement_id=e.id
        LEFT JOIN projets p     ON bt.projet_id=p.id
        WHERE 1=1"""
    params = []
    if user["role"] == "technicien":
        sql += " AND bt.technicien_username=?"; params.append(user["username"])
    statut  = request.args.get("statut","")
    type_bt = request.args.get("type","")
    limit   = int(request.args.get("limit", 500))
    if statut:  sql += " AND bt.statut=?";  params.append(statut)
    if type_bt: sql += " AND bt.type_bt=?"; params.append(type_bt)
    sql += f" ORDER BY bt.date_ouverture DESC LIMIT {limit}"
    return jsonify([dict(r) for r in db.execute(sql, params).fetchall()])

@app.route("/api/bons_travail/<int:bt_id>", methods=["GET"])
@require_auth
def get_bon_travail(bt_id):
    db  = get_db()
    row = db.execute("""
        SELECT bt.*, COALESCE(e.nom,'') AS equipement, COALESCE(p.titre,'') AS projet
        FROM bons_travail bt
        LEFT JOIN equipements e ON bt.equipement_id=e.id
        LEFT JOIN projets p     ON bt.projet_id=p.id
        WHERE bt.id=?""", (bt_id,)).fetchone()
    if not row: return jsonify({"error": "Non trouvé"}), 404
    return jsonify(dict(row))

@app.route("/api/bons_travail", methods=["POST"])
@require_auth
def create_bon_travail():
    user  = request.user
    data  = request.json or {}
    titre = (data.get("titre") or "").strip()
    if not titre: return jsonify({"error": "Titre requis"}), 400
    db     = get_db()
    count  = db.execute("SELECT COUNT(*) FROM bons_travail").fetchone()[0] + 1
    numero = f"BT{count:05d}"
    db.execute("""
        INSERT INTO bons_travail
        (numero_bt,type_bt,titre,description,priorite,statut,
         technicien_username,date_ouverture,date_prevue,heure_prevue,
         equipement_id,projet_id,notes,created_by,updated_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (numero, data.get("type_bt","Dépannage"), titre,
         data.get("description",""), data.get("priorite","Normale"),
         data.get("statut","Ouvert"),
         data.get("technicien_username", user["username"]),
         data.get("date_ouverture", today()),
         data.get("date_prevue",""), data.get("heure_prevue",""),
         data.get("equipement_id") or None, data.get("projet_id") or None,
         data.get("notes",""),
         user["username"], user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id, "numero_bt": numero}), 201

@app.route("/api/bons_travail/<int:bt_id>", methods=["PATCH"])
@require_auth
def update_bon_travail(bt_id):
    user   = request.user
    data   = request.json or {}
    db     = get_db()
    fields = ["statut","priorite","notes","date_prevue","heure_prevue",
              "technicien_username","description","titre","type_bt"]
    sets, params = [], []
    for f in fields:
        if f in data: sets.append(f"{f}=?"); params.append(data[f])
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_by=?","updated_at=?"]; params += [user["username"], now(), bt_id]
    db.execute(f"UPDATE bons_travail SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/bons_travail/<int:bt_id>", methods=["DELETE"])
@require_role("admin")
def delete_bon_travail(bt_id):
    db = get_db()
    db.execute("DELETE FROM bons_travail WHERE id=?", (bt_id,))
    db.commit()
    return jsonify({"ok": True})

# BT modifiés depuis un timestamp (polling léger)
@app.route("/api/bons_travail/since/<ts>", methods=["GET"])
@require_auth
def get_bts_since(ts):
    user = request.user
    db   = get_db()
    sql  = """
        SELECT bt.id, bt.numero_bt, bt.titre, bt.type_bt, bt.priorite, bt.statut,
               bt.date_ouverture, bt.technicien_username,
               COALESCE(e.nom,'') AS equipement, COALESCE(p.titre,'') AS projet
        FROM bons_travail bt
        LEFT JOIN equipements e ON bt.equipement_id=e.id
        LEFT JOIN projets p     ON bt.projet_id=p.id
        WHERE bt.created_at > ? OR bt.updated_at > ?"""
    params = [ts, ts]
    if user["role"] == "technicien":
        sql += " AND bt.technicien_username=?"
        params.append(user["username"])
    sql += " ORDER BY bt.id DESC LIMIT 50"
    return jsonify([dict(r) for r in db.execute(sql, params).fetchall()])

# ══════════════════════════════════════════════════════════════════════════════
#  PLANNING
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/planning", methods=["GET"])
@require_auth
def get_planning():
    user   = request.user
    db     = get_db()
    sql    = """
        SELECT pl.id, pl.numero_pl, pl.statut, pl.date_prevue, pl.heure_prevue, pl.heure_fin,
               pl.type_intervention, pl.technicien_username, pl.notes,
               COALESCE(e.nom,'') AS equipement, COALESCE(p.titre,'') AS projet
        FROM planning pl
        LEFT JOIN equipements e ON pl.equipement_id=e.id
        LEFT JOIN projets p     ON pl.projet_id=p.id
        WHERE 1=1"""
    params = []
    if user["role"] == "technicien":
        sql += " AND pl.technicien_username=?"; params.append(user["username"])
    date_from = request.args.get("from","")
    date_to   = request.args.get("to","")
    if date_from: sql += " AND pl.date_prevue >= ?"; params.append(date_from)
    if date_to:   sql += " AND pl.date_prevue <= ?"; params.append(date_to)
    sql += " ORDER BY pl.date_prevue ASC, pl.heure_prevue ASC LIMIT 500"
    return jsonify([dict(r) for r in db.execute(sql, params).fetchall()])

@app.route("/api/planning/<int:pl_id>", methods=["PATCH"])
@require_auth
def update_planning(pl_id):
    user   = request.user
    data   = request.json or {}
    db     = get_db()
    sets, params = [], []
    for f in ["statut","notes","date_realisation","heure_fin","date_prevue","heure_prevue"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f])
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_by=?","updated_at=?"]; params += [user["username"], now(), pl_id]
    db.execute(f"UPDATE planning SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  COMPTES RENDUS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/comptes_rendus", methods=["GET"])
@require_auth
def get_comptes_rendus():
    user   = request.user
    db     = get_db()
    sql    = """
        SELECT cr.id, cr.numero_cr, cr.date_intervention, cr.heure_debut, cr.heure_fin,
               cr.remarques, cr.statut, cr.total_heures, cr.intervenants,
               bt.titre AS bt_titre, bt.numero_bt,
               COALESCE(e.nom,'') AS equipement
        FROM comptes_rendus cr
        JOIN bons_travail bt    ON cr.bon_travail_id=bt.id
        LEFT JOIN equipements e ON bt.equipement_id=e.id
        WHERE 1=1"""
    params = []
    if user["role"] == "technicien":
        sql += " AND bt.technicien_username=?"; params.append(user["username"])
    bt_id = request.args.get("bt_id","")
    if bt_id: sql += " AND cr.bon_travail_id=?"; params.append(int(bt_id))
    sql += " ORDER BY cr.date_intervention DESC LIMIT 200"
    return jsonify([dict(r) for r in db.execute(sql, params).fetchall()])

@app.route("/api/bons_travail/<int:bt_id>/comptes_rendus", methods=["GET"])
@require_auth
def get_cr_by_bt(bt_id):
    db = get_db()
    rows = db.execute("""
        SELECT id, numero_cr, date_intervention, heure_debut, heure_fin,
               intervenants, remarques, statut, total_heures
        FROM comptes_rendus WHERE bon_travail_id=?
        ORDER BY date_intervention DESC""", (bt_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/comptes_rendus", methods=["POST"])
@require_auth
def create_compte_rendu():
    user  = request.user
    data  = request.json or {}
    bt_id = data.get("bon_travail_id")
    if not bt_id: return jsonify({"error": "bon_travail_id requis"}), 400
    db     = get_db()
    count  = db.execute("SELECT COUNT(*) FROM comptes_rendus").fetchone()[0] + 1
    numero = f"CR{count:05d}"
    db.execute("""
        INSERT INTO comptes_rendus
        (numero_cr,bon_travail_id,date_intervention,heure_debut,heure_fin,
         intervenants,remarques,statut,total_heures,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (numero, int(bt_id),
         data.get("date_intervention", today()),
         data.get("heure_debut",""), data.get("heure_fin",""),
         json.dumps(data.get("intervenants",[])),
         data.get("remarques",""), data.get("statut","En cours"),
         data.get("total_heures",""),
         user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id, "numero_cr": numero}), 201

@app.route("/api/comptes_rendus/<int:cr_id>", methods=["PATCH"])
@require_auth
def update_compte_rendu(cr_id):
    data   = request.json or {}
    db     = get_db()
    sets, params = [], []
    for f in ["date_intervention","heure_debut","heure_fin","remarques","statut","total_heures"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f])
    if "intervenants" in data:
        sets.append("intervenants=?"); params.append(json.dumps(data["intervenants"]))
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_at=?"]; params += [now(), cr_id]
    db.execute(f"UPDATE comptes_rendus SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
#  DONNÉES DE RÉFÉRENCE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/equipements", methods=["GET"])
@require_auth
def get_equipements():
    db     = get_db()
    search = request.args.get("q","")
    sql    = "SELECT id, nom, statut FROM equipements WHERE COALESCE(statut,'') != 'Résilié'"
    params = []
    if search:
        sql += " AND nom LIKE ?"; params.append(f"%{search}%")
    sql += " ORDER BY LOWER(nom) LIMIT 500"
    return jsonify([dict(r) for r in db.execute(sql, params).fetchall()])

@app.route("/api/projets", methods=["GET"])
@require_auth
def get_projets():
    db = get_db()
    return jsonify([dict(r) for r in db.execute(
        "SELECT id, titre FROM projets ORDER BY LOWER(titre) LIMIT 500").fetchall()])

@app.route("/api/techniciens", methods=["GET"])
@require_auth
def get_techniciens():
    db = get_db()
    return jsonify([dict(r) for r in db.execute(
        "SELECT username, full_name, role FROM utilisateurs "
        "WHERE role IN ('technicien','admin') AND is_active=1 ORDER BY full_name").fetchall()])

@app.route("/api/clients", methods=["GET"])
@require_auth
def get_clients():
    db = get_db()
    return jsonify([dict(r) for r in db.execute(
        "SELECT id, nom FROM clients ORDER BY LOWER(nom) LIMIT 500").fetchall()])

@app.route("/api/domaines", methods=["GET"])
@require_auth
def get_domaines():
    db = get_db()
    try:
        return jsonify([dict(r) for r in db.execute(
            "SELECT id, nom FROM domaines ORDER BY nom").fetchall()])
    except Exception:
        return jsonify([])

# ══════════════════════════════════════════════════════════════════════════════
#  GAMMES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/gammes", methods=["GET"])
@require_auth
def get_gammes():
    db = get_db()
    try:
        rows = db.execute("""
            SELECT g.id, g.nom, g.description, g.periodicite,
                   COALESCE(d.nom,'') AS domaine
            FROM gammes g
            LEFT JOIN domaines d ON g.domaine_id=d.id
            ORDER BY g.nom LIMIT 200""").fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/gammes/<int:g_id>/operations", methods=["GET"])
@require_auth
def get_operations_gamme(g_id):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT * FROM operations_gamme WHERE gamme_id=? ORDER BY ordre",
            (g_id,)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  TECHNIQUE — Installations
# ══════════════════════════════════════════════════════════════════════════════

TECHNIQUE_MAP = {
    "ups": "UPS", "ht": "Haute tension", "ge": "Groupe électrogène",
    "es": "Eclairage de secours", "di": "Détection incendie", "des": "Désenfumage",
}

def _get_installations(prefix, search=""):
    db  = get_db()
    sql = f"""
        SELECT COALESCE(pj.titre,'—') AS projet, u.designation_ups, u.marque,
               u.type_ups, u.puissance, u.numero_serie, u.mise_en_service, u.id
        FROM {prefix}_installations u
        LEFT JOIN equipements e ON u.idmat_id=e.id
        LEFT JOIN projets pj    ON e.client_id=pj.id
        WHERE COALESCE(e.statut,'') != 'Résilié'"""
    params = []
    if search:
        sql += " AND (pj.titre LIKE ? OR u.designation_ups LIKE ? OR u.numero_serie LIKE ?)"
        params += [f"%{search}%"]*3
    sql += " ORDER BY pj.titre ASC, u.designation_ups ASC LIMIT 300"
    rows = db.execute(sql, params).fetchall()
    cols = ["projet","designation","marque","type","puissance","serie","mes","id"]
    return [dict(zip(cols, r)) for r in rows]

def _technique_route(prefix):
    user   = request.user
    search = request.args.get("search","")
    access = user.get("technique_access","Toutes")
    if access != "Toutes" and TECHNIQUE_MAP.get(prefix) != access:
        return jsonify({"error": "Accès non autorisé"}), 403
    try:
        return jsonify(_get_installations(prefix, search))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

for _prefix in ["ups","ht","ge","es","di","des"]:
    def _make_route(p):
        @app.route(f"/api/technique/{p}", methods=["GET"])
        @require_auth
        def _fn(*a, _p=p, **kw):
            return _technique_route(_p)
        _fn.__name__ = f"technique_{p}"
        return _fn
    _make_route(_prefix)

# ══════════════════════════════════════════════════════════════════════════════
#  STATISTIQUES (Dashboard)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/stats", methods=["GET"])
@require_auth
def get_stats():
    db = get_db()
    try:
        bt_open    = db.execute("SELECT COUNT(*) FROM bons_travail WHERE statut='Ouvert'").fetchone()[0]
        bt_encours = db.execute("SELECT COUNT(*) FROM bons_travail WHERE statut='En cours'").fetchone()[0]
        bt_urgent  = db.execute("SELECT COUNT(*) FROM bons_travail WHERE priorite='Urgente' AND statut != 'Terminé'").fetchone()[0]
        bt_termine = db.execute("SELECT COUNT(*) FROM bons_travail WHERE statut='Terminé'").fetchone()[0]
        plan_today = db.execute("SELECT COUNT(*) FROM planning WHERE date_prevue=?", (today(),)).fetchone()[0]
        equip_tot  = db.execute("SELECT COUNT(*) FROM equipements WHERE COALESCE(statut,'') != 'Résilié'").fetchone()[0]
        return jsonify({
            "bt_open":    bt_open,
            "bt_encours": bt_encours,
            "bt_urgent":  bt_urgent,
            "bt_termine": bt_termine,
            "plan_today": plan_today,
            "equip_total":equip_tot,
            "server_time":now(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  SYNCHRONISATION PC → CLOUD
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/sync", methods=["POST"])
def sync_from_pc():
    if request.headers.get("X-Sync-Secret","") != SYNC_SECRET:
        return jsonify({"error": "Clé de sync invalide"}), 403
    payload    = request.json or {}
    tables     = payload.get("tables", {})
    if not tables: return jsonify({"error": "Aucune donnée reçue"}), 400
    db         = get_db()
    total_rows = 0
    errors     = []
    for table_name, rows in tables.items():
        if not rows: continue
        try:
            cols         = list(rows[0].keys())
            cols_sql     = ", ".join(cols)
            placeholders = ", ".join(["?"] * len(cols))
            for row in rows:
                try:
                    db.execute(
                        f"INSERT OR REPLACE INTO {table_name} ({cols_sql}) VALUES ({placeholders})",
                        [row.get(c) for c in cols])
                    total_rows += 1
                except Exception as e:
                    errors.append(f"{table_name}: {e}")
        except Exception as e:
            errors.append(f"{table_name}: {e}")
    db.commit()
    return jsonify({"ok": True, "rows_synced": total_rows, "errors": errors[:10]})

@app.route("/api/sync/status", methods=["GET"])
def sync_status():
    if request.headers.get("X-Sync-Secret","") != SYNC_SECRET:
        return jsonify({"error": "Clé invalide"}), 403
    try:
        db = get_db()
        return jsonify({
            "status":       "ok",
            "db":           DB_PATH,
            "bons_travail": db.execute("SELECT COUNT(*) FROM bons_travail").fetchone()[0],
            "planning":     db.execute("SELECT COUNT(*) FROM planning").fetchone()[0],
            "utilisateurs": db.execute("SELECT COUNT(*) FROM utilisateurs").fetchone()[0],
            "server_time":  now(),
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
#  DÉMARRAGE LOCAL
# ══════════════════════════════════════════════════════════════════════════════

# ── CLIENTS ───────────────────────────────────────────────────────────────────

@app.route("/api/clients", methods=["GET"])
@require_auth
def get_clients_full():
    db = get_db()
    search = request.args.get("q","")
    sql = "SELECT * FROM clients WHERE 1=1"
    params = []
    if search:
        sql += " AND (nom LIKE ? OR societe LIKE ? OR email LIKE ?)"
        params += [f"%{search}%"]*3
    sql += " ORDER BY COALESCE(societe,nom) LIMIT 500"
    return jsonify([dict(r) for r in db.execute(sql, params).fetchall()])

@app.route("/api/clients", methods=["POST"])
@require_auth
def create_client():
    user = request.user
    data = request.json or {}
    nom  = (data.get("nom") or "").strip()
    if not nom: return jsonify({"error": "Nom requis"}), 400
    db = get_db()
    db.execute("""INSERT INTO clients (nom, societe, prenom, email, telephone, notes, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (nom, data.get("societe",""), data.get("prenom",""),
         data.get("email",""), data.get("telephone",""),
         data.get("notes",""), now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id}), 201

@app.route("/api/clients/<int:cl_id>", methods=["PATCH"])
@require_auth
def update_client(cl_id):
    data = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["nom","societe","prenom","email","telephone","notes"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f])
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_at=?"]; params += [now(), cl_id]
    db.execute(f"UPDATE clients SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ── PROJETS ───────────────────────────────────────────────────────────────────

@app.route("/api/projets", methods=["POST"])
@require_auth
def create_projet():
    user = request.user
    data = request.json or {}
    titre = (data.get("titre") or "").strip()
    if not titre: return jsonify({"error": "Titre requis"}), 400
    db = get_db()
    db.execute("""INSERT INTO projets (titre, numero_projet, client_id, gestionnaire_username, description, notes, created_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (titre, data.get("numero_projet",""),
         data.get("client_id") or None, data.get("gestionnaire_username") or None,
         data.get("description",""), data.get("notes",""),
         user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id}), 201

@app.route("/api/projets/<int:pj_id>", methods=["PATCH"])
@require_auth
def update_projet(pj_id):
    data = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["titre","numero_projet","client_id","gestionnaire_username","description","notes"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f] or None)
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_at=?"]; params += [now(), pj_id]
    db.execute(f"UPDATE projets SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ── ÉQUIPEMENTS (PATCH + POST) ────────────────────────────────────────────────

@app.route("/api/equipements", methods=["POST"])
@require_auth
def create_equipement():
    user = request.user
    data = request.json or {}
    nom  = (data.get("nom") or "").strip()
    if not nom: return jsonify({"error": "Nom requis"}), 400
    db = get_db()
    db.execute("""INSERT INTO equipements
        (nom, type_eq, marque, modele, numero_serie, emplacement, statut,
         client_id, periodicite, date_installation, notes, created_by, updated_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (nom, data.get("type_eq",""), data.get("marque",""), data.get("modele",""),
         data.get("numero_serie",""), data.get("emplacement",""),
         data.get("statut","En service"), data.get("client_id") or None,
         data.get("periodicite",""), data.get("date_installation") or None,
         data.get("notes",""), user["username"], user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id}), 201

@app.route("/api/equipements/<int:eq_id>", methods=["PATCH"])
@require_auth
def update_equipement(eq_id):
    user = request.user
    data = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["nom","type_eq","marque","modele","numero_serie","emplacement","statut","client_id","periodicite","date_installation","notes"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f] or None if f in ["client_id","date_installation"] else data[f])
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_by=?","updated_at=?"]; params += [user["username"], now(), eq_id]
    db.execute(f"UPDATE equipements SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ── GAMMES ────────────────────────────────────────────────────────────────────

@app.route("/api/gammes", methods=["POST"])
@require_auth
def create_gamme():
    user = request.user
    data = request.json or {}
    titre = (data.get("titre") or "").strip()
    if not titre: return jsonify({"error": "Titre requis"}), 400
    db = get_db()
    db.execute("""INSERT INTO gammes (titre, domaine, periodicite, equipement_id, duree_estimee, description, created_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (titre, data.get("domaine",""), data.get("periodicite",""),
         data.get("equipement_id") or None, data.get("duree_estimee",""),
         data.get("description",""), user["username"], now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id}), 201

@app.route("/api/gammes/<int:g_id>", methods=["PATCH"])
@require_auth
def update_gamme(g_id):
    data = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["titre","domaine","periodicite","equipement_id","duree_estimee","description"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f] or None if f == "equipement_id" else data[f])
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_at=?"]; params += [now(), g_id]
    db.execute(f"UPDATE gammes SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/gammes/<int:g_id>/operations", methods=["GET"])
@require_auth
def get_operations(g_id):
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM operations_gamme WHERE gamme_id=? ORDER BY ordre", (g_id,)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify([])

# ── UTILISATEURS ──────────────────────────────────────────────────────────────

@app.route("/api/utilisateurs", methods=["GET"])
@require_auth
def get_utilisateurs():
    db = get_db()
    return jsonify([dict(r) for r in db.execute(
        "SELECT id, username, full_name, email, role, lang, is_active, technique_access FROM utilisateurs ORDER BY full_name"
    ).fetchall()])

@app.route("/api/utilisateurs", methods=["POST"])
@require_role("admin","gestionnaire")
def create_utilisateur():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password: return jsonify({"error": "Identifiant et mot de passe requis"}), 400
    db = get_db()
    try:
        db.execute("""INSERT INTO utilisateurs (username, password_hash, full_name, email, role, lang, is_active, created_at)
            VALUES (?,?,?,?,?,?,1,?)""",
            (username, hash_pw(password), data.get("full_name",""),
             data.get("email",""), data.get("role","technicien"),
             data.get("lang","fr"), now()))
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return jsonify({"id": new_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/utilisateurs/<int:u_id>", methods=["PATCH"])
@require_role("admin","gestionnaire")
def update_utilisateur(u_id):
    data = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["full_name","email","role","lang","is_active","technique_access"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f])
    if "password" in data and data["password"]:
        sets.append("password_hash=?"); params.append(hash_pw(data["password"]))
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    params.append(u_id)
    db.execute(f"UPDATE utilisateurs SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

# ── ÉQUIPES ───────────────────────────────────────────────────────────────────

@app.route("/api/equipes", methods=["GET"])
@require_auth
def get_equipes():
    db = get_db()
    try:
        return jsonify([dict(r) for r in db.execute(
            "SELECT * FROM equipes ORDER BY nom").fetchall()])
    except Exception:
        return jsonify([])

@app.route("/api/equipes", methods=["POST"])
@require_auth
def create_equipe():
    user = request.user
    data = request.json or {}
    nom  = (data.get("nom") or "").strip()
    if not nom: return jsonify({"error": "Nom requis"}), 400
    db = get_db()
    db.execute("""INSERT INTO equipes (nom, description, gestionnaire_username, created_at, updated_at)
        VALUES (?,?,?,?,?)""",
        (nom, data.get("description",""),
         data.get("gestionnaire_username") or None, now(), now()))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"id": new_id}), 201

@app.route("/api/equipes/<int:eq_id>", methods=["PATCH"])
@require_auth
def update_equipe(eq_id):
    data = request.json or {}
    db   = get_db()
    sets, params = [], []
    for f in ["nom","description","gestionnaire_username"]:
        if f in data: sets.append(f"{f}=?"); params.append(data[f] or None)
    if not sets: return jsonify({"error": "Rien à mettre à jour"}), 400
    sets += ["updated_at=?"]; params += [now(), eq_id]
    db.execute(f"UPDATE equipes SET {', '.join(sets)} WHERE id=?", params)
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/equipes/<int:eq_id>/membres", methods=["GET"])
@require_auth
def get_membres_equipe(eq_id):
    db = get_db()
    try:
        rows = db.execute("""
            SELECT et.technicien_username, COALESCE(u.full_name, et.technicien_username) AS full_name
            FROM equipe_techniciens et
            LEFT JOIN utilisateurs u ON et.technicien_username = u.username
            WHERE et.equipe_id=?""", (eq_id,)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])


if __name__ == "__main__":
    import socket
    try:    ip = socket.gethostbyname(socket.gethostname())
    except: ip = "127.0.0.1"
    print("=" * 60)
    print("  SOCOM GMAO — Serveur v2")
    print(f"  Interface PC     : http://127.0.0.1:5000/pc")
    print(f"  Interface Mobile : http://127.0.0.1:5000/")
    print(f"  Réseau local     : http://{ip}:5000")
    print(f"  DB               : {DB_PATH}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
