"""
SOCOM GMAO — Backend v3.1
"""
import hashlib, json, os, sqlite3, smtplib, io
from datetime import datetime, date, timedelta
from functools import wraps
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")

BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.environ.get("GMAO_DB", str(BASE_DIR / "gmao.db"))

@app.route("/")
def index():
    f = BASE_DIR / "index.html"
    return send_file(str(f)) if f.exists() else ("index.html introuvable", 404)

@app.route("/mobile")
def mobile():
    f = BASE_DIR / "gmao_mobile.html"
    return send_file(str(f)) if f.exists() else ("gmao_mobile.html introuvable", 404)

@app.route("/sw.js")
def sw():
    f = BASE_DIR / "sw.js"
    return Response(f.read_text(), mimetype="application/javascript",
                    headers={"Service-Worker-Allowed": "/"}) if f.exists() else ("", 404)

@app.route("/manifest.json")
def manifest():
    return jsonify({"name":"GMAO Terrain","short_name":"GMAO","start_url":"/mobile",
                    "display":"standalone","background_color":"#1e293b","theme_color":"#3b82f6"})

@app.route("/health")
def health():
    try: get_db().execute("SELECT 1"); return jsonify({"status":"ok","time":now()})
    except Exception as e: return jsonify({"status":"error","error":str(e)}),500

def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()
def now(): return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
def today(): return date.today().isoformat()
def rows(cur): return [dict(r) for r in cur.fetchall()]
def one(cur): r = cur.fetchone(); return dict(r) if r else None
def to_int(v):
    try: return int(v) if v not in (None,"","null") else None
    except: return None

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        auth = request.headers.get("Authorization","")
        if not auth.startswith("Bearer "): return jsonify({"error":"Non authentifie"}),401
        token = auth[7:]; parts = token.split(":")
        if len(parts)!=2: return jsonify({"error":"Token invalide"}),401
        uid = to_int(parts[0]); db = get_db()
        u = one(db.execute("SELECT * FROM utilisateurs WHERE id=? AND actif=1",(uid,)))
        if not u or hp(f"{uid}:{u['email']}:{u['password']}")!=parts[1]:
            return jsonify({"error":"Token invalide"}),401
        request.user = u; return fn(*a,**k)
    return wrapper

def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a,**k):
            auth = request.headers.get("Authorization","")
            if not auth.startswith("Bearer "): return jsonify({"error":"Non authentifie"}),401
            token = auth[7:]; parts = token.split(":")
            if len(parts)!=2: return jsonify({"error":"Token invalide"}),401
            uid = to_int(parts[0]); db = get_db()
            u = one(db.execute("SELECT * FROM utilisateurs WHERE id=? AND actif=1",(uid,)))
            if not u or hp(f"{uid}:{u['email']}:{u['password']}")!=parts[1]:
                return jsonify({"error":"Token invalide"}),401
            if u["role"] not in roles: return jsonify({"error":"Acces refuse"}),403
            request.user = u; return fn(*a,**k)
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
    except Exception as e: print(f"[MAIL] {e}")

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
                crs=rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
                for cr in crs:
                    try:
                        cr["intervenants"]=rows(db.execute("""SELECT ci.*,COALESCE(u2.nom,ci.nom,'') AS nom
                            FROM cr_intervenants ci LEFT JOIN utilisateurs u2 ON ci.utilisateur_id=u2.id
                            WHERE ci.cr_id=?""",(cr["id"],)))
                    except: cr["intervenants"]=[]
                def mf(field): return "\n".join([cr.get(field,"") for cr in crs if cr.get(field,"")])
                all_ivs,seen=[],set()
                for cr in crs:
                    for iv in cr.get("intervenants",[]):
                        k=(iv.get("nom",""),iv.get("date",""))
                        if k not in seen: seen.add(k); all_ivs.append(iv)
                date_iv=(mf("date_intervention") or (r.get("date_realisation") or today()))
                date_iv=date_iv.split("\n")[0][:10]
                tr="RAPPORT D'INTERVENTION - DEPANNAGE" if r["type"]=="DEPANNAGE" else "RAPPORT D'INTERVENTION"
                pdf_bytes=generate_rapport({"titre_rapport":tr,"titre":r["designation"],"client":r["projet"],
                    "numero_projet":"--","numero_iv":r["numero"],"type_label":r["type"],"date":date_iv,
                    "equipement":r["designation"],"localisation":"--","intervenants":"--",
                    "intervenants_list":all_ivs,"observations":mf("observations"),
                    "actions_realisees":mf("actions_realisees"),"mesures":mf("mesures"),
                    "recommandations":mf("recommandations"),"conclusion":mf("conclusion")})
                attachments.append((f"rapport_{r['numero']}.pdf",pdf_bytes))
            except Exception as pe: print(f"[PDF] {pe}")
        send_mail(r["mgr_email"],f"[GMAO] {action} - {r['numero']}",
            f"Bonjour {r['mgr_nom']},\n\n{action}\n\nRef: {r['numero']}\nType: {r['type']}\nStatut: {r['statut']}\nEquipement: {r['designation']}\nProjet: {r['projet']}\n\nCordialement,\nSOCOM GMAO",
            attachments=attachments or None)
    except Exception as e: print(f"[NOTIFY] {e}")

def init_db():
    db=get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'technicien'
            CHECK(role IN ('admin','manager','technicien')),
        actif INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now'))
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
            CHECK(statut IN ('PLANIFIEE','EN_COURS','TERMINEE','ANNULEE')),
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
    CREATE TABLE IF NOT EXISTS smtp_config (
        id INTEGER PRIMARY KEY DEFAULT 1, host TEXT DEFAULT '',
        port INTEGER DEFAULT 587, username TEXT DEFAULT '', password TEXT DEFAULT '',
        sender_email TEXT DEFAULT '', sender_name TEXT DEFAULT 'SOCOM GMAO',
        use_tls INTEGER DEFAULT 1, enabled INTEGER DEFAULT 0
    );
    INSERT OR IGNORE INTO smtp_config (id) VALUES (1);
    """)
    db.commit()
    try:
        db.execute("INSERT OR IGNORE INTO utilisateurs (nom,email,password,role) VALUES (?,?,?,?)",
                   ("Administrateur","admin@gmao.fr",hp("admin"),"admin"))
        db.commit()
    except: pass

with app.app_context(): init_db()


# ══ DASHBOARD ══
@app.route("/api/dashboard")
@require_auth
def get_dashboard():
    db = get_db()
    u  = request.user
    if u["role"] == "technicien":
        ivs = rows(db.execute("""SELECT i.*,e.designation AS equip_nom,p.nom AS projet_nom
            FROM interventions i JOIN equipements e ON i.equipement_id=e.id
            JOIN projets p ON e.projet_id=p.id
            WHERE (i.technicien_id=? OR i.equipe_id IN (
                SELECT equipe_id FROM equipe_membres WHERE technicien_id=?))
            AND i.statut NOT IN ('TERMINEE','ANNULEE')
            ORDER BY i.date_prevue LIMIT 20""", (u["id"], u["id"])))
    else:
        ivs = rows(db.execute("""SELECT i.*,e.designation AS equip_nom,p.nom AS projet_nom
            FROM interventions i JOIN equipements e ON i.equipement_id=e.id
            JOIN projets p ON e.projet_id=p.id
            WHERE i.statut NOT IN ('TERMINEE','ANNULEE')
            ORDER BY i.date_prevue LIMIT 20"""))
    alertes = rows(db.execute("""SELECT p.*,e.designation AS equip_nom,pr.nom AS projet_nom
        FROM pieces p JOIN equipements e ON p.equipement_id=e.id
        JOIN projets pr ON e.projet_id=pr.id
        WHERE p.statut IN ('A_SURVEILLER','A_REMPLACER') ORDER BY p.statut DESC LIMIT 10"""))
    critiques = rows(db.execute("""SELECT e.*,p.nom AS projet_nom FROM equipements e
        JOIN projets p ON e.projet_id=p.id
        WHERE e.id IN (SELECT DISTINCT equipement_id FROM pieces WHERE statut='A_REMPLACER') LIMIT 10"""))
    stats = {
        "total_equipements": one(db.execute("SELECT COUNT(*) AS n FROM equipements"))["n"],
        "total_interventions": one(db.execute("SELECT COUNT(*) AS n FROM interventions"))["n"],
        "interventions_en_cours": one(db.execute("SELECT COUNT(*) AS n FROM interventions WHERE statut='EN_COURS'"))["n"],
        "interventions_planifiees": one(db.execute("SELECT COUNT(*) AS n FROM interventions WHERE statut='PLANIFIEE'"))["n"],
        "pieces_alertes": one(db.execute("SELECT COUNT(*) AS n FROM pieces WHERE statut IN ('A_SURVEILLER','A_REMPLACER')"))["n"],
    }
    return jsonify({"interventions": ivs, "alertes": alertes, "critiques": critiques, "stats": stats})

# ══ AUTH ══
@app.route("/api/login",methods=["POST"])
def login():
    d=request.json or {}; db=get_db()
    u=one(db.execute("SELECT * FROM utilisateurs WHERE email=? AND actif=1",(d.get("email",""),)))
    if not u or u["password"]!=hp(d.get("password","")): return jsonify({"error":"Email ou mot de passe incorrect"}),401
    token=f"{u['id']}:{hp(str(u['id'])+':'+u['email']+':'+u['password'])}"
    return jsonify({"token":token,"user":{"id":u["id"],"nom":u["nom"],"email":u["email"],"role":u["role"]}})

# ══ UTILISATEURS ══
@app.route("/api/utilisateurs")
@require_auth
def get_utilisateurs():
    return jsonify(rows(get_db().execute("SELECT id,nom,email,role,actif FROM utilisateurs ORDER BY nom")))

@app.route("/api/utilisateurs",methods=["POST"])
@require_role("admin","manager")
def create_utilisateur():
    d=request.json or {}
    if not all([d.get("nom"),d.get("email"),d.get("password")]): return jsonify({"error":"nom,email,password requis"}),400
    db=get_db()
    try:
        db.execute("INSERT INTO utilisateurs (nom,email,password,role) VALUES (?,?,?,?)",
                   (d["nom"],d["email"],hp(d["password"]),d.get("role","technicien")))
        db.commit(); return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201
    except Exception as e: return jsonify({"error":str(e)}),400

@app.route("/api/utilisateurs/<int:uid>",methods=["PATCH"])
@require_role("admin","manager")
def update_utilisateur(uid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["nom","email","role","actif"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if "password" in d and d["password"]: sets.append("password=?"); params.append(hp(d["password"]))
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(uid); db.execute(f"UPDATE utilisateurs SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/utilisateurs/<int:uid>",methods=["DELETE"])
@require_role("admin")
def delete_utilisateur(uid):
    if uid==request.user["id"]: return jsonify({"error":"Impossible de supprimer son propre compte"}),400
    db=get_db(); db.execute("DELETE FROM utilisateurs WHERE id=?",(uid,)); db.commit()
    return jsonify({"ok":True})

@app.route("/api/utilisateurs/me",methods=["PATCH"])
@require_auth
def update_me():
    d=request.json or {}; db=get_db(); uid=request.user["id"]; sets,params=[],[]
    if "nom" in d: sets.append("nom=?"); params.append(d["nom"])
    if "password" in d and d["password"]: sets.append("password=?"); params.append(hp(d["password"]))
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(uid); db.execute(f"UPDATE utilisateurs SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

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
    return jsonify(rows(db.execute("""SELECT p.*,c.societe AS client_nom,m.nom AS manager_nom
        FROM projets p LEFT JOIN clients c ON p.client_id=c.id
        LEFT JOIN utilisateurs m ON p.manager_id=m.id ORDER BY p.nom""")))

@app.route("/api/projets",methods=["POST"])
@require_role("admin","manager")
def create_projet():
    d=request.json or {}
    if not d.get("nom"): return jsonify({"error":"nom requis"}),400
    db=get_db(); num=d.get("numero_projet") or next_numero(db,"P","projets","numero_projet")
    db.execute("INSERT INTO projets (numero_projet,nom,client_id,manager_id,description,date_debut,date_fin,statut) VALUES (?,?,?,?,?,?,?,?)",
               (num,d["nom"],to_int(d.get("client_id")),to_int(d.get("manager_id")),
                d.get("description",""),d.get("date_debut") or None,d.get("date_fin") or None,d.get("statut","EN_COURS")))
    db.commit(); return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201

@app.route("/api/projets/<int:pid>",methods=["PATCH"])
@require_role("admin","manager")
def update_projet(pid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["nom","client_id","manager_id","description","date_debut","date_fin","statut","numero_projet"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(pid); db.execute(f"UPDATE projets SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    return jsonify({"ok":True})

@app.route("/api/projets/<int:pid>",methods=["DELETE"])
@require_role("admin")
def delete_projet(pid):
    db=get_db(); db.execute("DELETE FROM projets WHERE id=?",(pid,)); db.commit()
    return jsonify({"ok":True})

# ══ EQUIPEMENTS ══
@app.route("/api/equipements")
@require_auth
def get_equipements():
    db=get_db()
    sql="""SELECT e.*,p.nom AS projet_nom,p.numero_projet,g.nom AS gamme_nom,t.nom AS technique_nom
           FROM equipements e JOIN projets p ON e.projet_id=p.id
           LEFT JOIN gammes g ON e.gamme_id=g.id
           LEFT JOIN techniques t ON e.technique_id=t.id WHERE 1=1"""
    params=[]
    if request.args.get("projet_id"): sql+=" AND e.projet_id=?"; params.append(request.args["projet_id"])
    equips=rows(db.execute(sql+" ORDER BY p.nom,e.designation",params))
    for e in equips:
        e["criticite"]=criticite(e["id"],db)
        e["nb_maintenance"]=db.execute("SELECT COUNT(*) FROM interventions WHERE equipement_id=? AND type='MAINTENANCE'",(e["id"],)).fetchone()[0]
        e["nb_depannage"]=db.execute("SELECT COUNT(*) FROM interventions WHERE equipement_id=? AND type='DEPANNAGE'",(e["id"],)).fetchone()[0]
        e["gammes"]=rows(db.execute("SELECT g.* FROM gammes g JOIN equipement_gammes eg ON g.id=eg.gamme_id WHERE eg.equipement_id=? ORDER BY g.nom",(e["id"],)))
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
    e["gammes"]=rows(db.execute("SELECT g.* FROM gammes g JOIN equipement_gammes eg ON g.id=eg.gamme_id WHERE eg.equipement_id=? ORDER BY g.nom",(eid,)))
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
    for gid in d.get("gammes",[]):
        try: db.execute("INSERT OR IGNORE INTO equipement_gammes VALUES (?,?)",(new_eid,int(gid)))
        except: pass
    db.commit(); return jsonify({"id":new_eid}),201

@app.route("/api/equipements/<int:eid>",methods=["PATCH"])
@require_role("admin","manager")
def update_equipement(eid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["designation","type_technique","localisation","marque","modele","puissance","numero_serie","in_out","date_mise_en_service","statut","technique_id","notes"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if sets: params.append(eid); db.execute(f"UPDATE equipements SET {chr(44).join(sets)} WHERE id=?",params)
    if "gammes" in d:
        db.execute("DELETE FROM equipement_gammes WHERE equipement_id=?",(eid,))
        for gid in d["gammes"]:
            try: db.execute("INSERT OR IGNORE INTO equipement_gammes VALUES (?,?)",(eid,int(gid)))
            except: pass
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
        except: pass
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
    params.append(pid); db.execute(f"UPDATE pieces SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
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
        except: pass
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
            except: pass
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
                  u.nom AS technicien_nom,eq.nom AS equipe_nom
           FROM interventions i JOIN equipements e ON i.equipement_id=e.id
           JOIN projets p ON e.projet_id=p.id LEFT JOIN clients c ON p.client_id=c.id
           LEFT JOIN utilisateurs u ON i.technicien_id=u.id
           LEFT JOIN equipes eq ON i.equipe_id=eq.id WHERE 1=1"""
    params=[]
    if u["role"]=="technicien":
        sql+=" AND (i.technicien_id=? OR i.equipe_id IN (SELECT equipe_id FROM equipe_membres WHERE technicien_id=?))"
        params+=[u["id"],u["id"]]
    for arg,col in [("type","i.type"),("statut","i.statut"),("equipement_id","i.equipement_id"),("projet_id","e.projet_id")]:
        if request.args.get(arg): sql+=f" AND {col}=?"; params.append(request.args[arg])
    return jsonify(rows(db.execute(sql+" ORDER BY i.created_at DESC",params)))

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
    i["comptes_rendus"]=crs; return jsonify(i)

@app.route("/api/interventions",methods=["POST"])
@require_auth
def create_intervention():
    d=request.json or {}
    if not d.get("equipement_id"): return jsonify({"error":"equipement_id requis"}),400
    db=get_db(); num=next_numero(db,"INT","interventions","numero")
    db.execute("INSERT INTO interventions (numero,equipement_id,technicien_id,equipe_id,type,statut,date_prevue,description) VALUES (?,?,?,?,?,?,?,?)",
               (num,d["equipement_id"],to_int(d.get("technicien_id")),to_int(d.get("equipe_id")),
                d.get("type","MAINTENANCE"),d.get("statut","PLANIFIEE"),d.get("date_prevue") or None,d.get("description","")))
    db.commit(); iid=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    notify(iid,"Nouvelle intervention creee"); return jsonify({"id":iid,"numero":num}),201

@app.route("/api/interventions/<int:iid>",methods=["PATCH"])
@require_auth
def update_intervention(iid):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["technicien_id","equipe_id","type","statut","date_prevue","date_realisation","description","rapport"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if "statut" in d and d["statut"]=="TERMINEE": sets.append("date_realisation=?"); params.append(now())
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(iid); db.execute(f"UPDATE interventions SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
    notify(iid,f"Intervention mise a jour : {d.get('statut','')}"); return jsonify({"ok":True})

@app.route("/api/interventions/<int:iid>",methods=["DELETE"])
@require_role("admin","manager")
def delete_intervention(iid):
    db=get_db(); db.execute("DELETE FROM comptes_rendus WHERE intervention_id=?",(iid,))
    db.execute("DELETE FROM interventions WHERE id=?",(iid,)); db.commit()
    return jsonify({"ok":True})

# ══ COMPTES RENDUS ══
@app.route("/api/comptes_rendus/<int:iid>")
@require_auth
def get_comptes_rendus(iid):
    db=get_db(); crs=rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
    for cr in crs:
        try:
            cr["intervenants"]=rows(db.execute("""SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
                FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id WHERE ci.cr_id=?""",(cr["id"],)))
        except: cr["intervenants"]=[]
    return jsonify(crs)

@app.route("/api/comptes_rendus/<int:iid>",methods=["POST"])
@require_auth
def create_compte_rendu(iid):
    d=request.json or {}; db=get_db()
    th = sum(float(iv.get("total_heures",0)) for iv in d.get("intervenants",[]))
    db.execute("INSERT INTO comptes_rendus (intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,total_heures) VALUES (?,?,?,?,?,?,?,?)",
               (iid,d.get("date_intervention") or None,d.get("observations",""),d.get("actions_realisees",""),d.get("mesures",""),d.get("recommandations",""),d.get("conclusion",""),th))
    db.commit(); cr_id=db.execute("SELECT last_insert_rowid()").fetchone()[0]
    # Stocker intervenants dans cr_intervenants si table existe
    try:
        for iv in d.get("intervenants",[]):
            db.execute("INSERT INTO cr_intervenants (cr_id,utilisateur_id,nom,date,heure_debut,heure_fin,total_heures) VALUES (?,?,?,?,?,?,?)",
                       (cr_id,to_int(iv.get("utilisateur_id")),iv.get("nom",""),iv.get("date",""),iv.get("heure_debut",""),iv.get("heure_fin",""),iv.get("total_heures",0)))
        db.commit()
    except: pass
    return jsonify({"id":cr_id}),201

@app.route("/api/comptes_rendus/cr/<int:cr_id>",methods=["PATCH"])
@require_role("admin","manager")
def update_compte_rendu(cr_id):
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["date_intervention","observations","actions_realisees","mesures","recommandations","conclusion","total_heures"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if sets: params.append(cr_id); db.execute(f"UPDATE comptes_rendus SET {chr(44).join(sets)} WHERE id=?",params)
    if "intervenants" in d:
        db.execute("DELETE FROM cr_intervenants WHERE cr_id=?",(cr_id,))
        for iv in d["intervenants"]:
            db.execute("INSERT INTO cr_intervenants (cr_id,utilisateur_id,nom,date,heure_debut,heure_fin,total_heures) VALUES (?,?,?,?,?,?,?)",
                       (cr_id,to_int(iv.get("utilisateur_id")),iv.get("nom",""),iv.get("date",""),iv.get("heure_debut",""),iv.get("heure_fin",""),iv.get("total_heures",0)))
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
            for row in data_rows: ws.append(row)
            for col in ws.columns: ws.column_dimensions[col[0].column_letter].width=max(len(str(c.value or "")) for c in col)+4
        ws=wb.active; ws.title="Equipements"
        make_sheet(ws,["ID","Designation","Type","Projet","Localisation","Marque","Modele","Statut"],
            [(e["id"],e["designation"],e["type_technique"],e.get("projet_nom",""),e.get("localisation",""),e.get("marque",""),e.get("modele",""),e["statut"])
             for e in rows(db.execute("SELECT e.*,p.nom AS projet_nom FROM equipements e JOIN projets p ON e.projet_id=p.id ORDER BY p.nom,e.designation"))])
        ws2=wb.create_sheet("Interventions")
        make_sheet(ws2,["Numero","Type","Statut","Equipement","Projet","Technicien","Date prevue","Date realisation"],
            [(i["numero"],i["type"],i["statut"],i.get("equip_nom",""),i.get("projet_nom",""),i.get("technicien_nom",""),i.get("date_prevue",""),i.get("date_realisation",""))
             for i in rows(db.execute("""SELECT i.*,e.designation AS equip_nom,p.nom AS projet_nom,u.nom AS technicien_nom
                FROM interventions i JOIN equipements e ON i.equipement_id=e.id JOIN projets p ON e.projet_id=p.id
                LEFT JOIN utilisateurs u ON i.technicien_id=u.id ORDER BY i.created_at DESC"""))])
        ws3=wb.create_sheet("Pieces")
        make_sheet(ws3,["ID","Type","Equipement","Projet","Qte","Reference","Date install","Duree vie","Fin de vie","Statut"],
            [(p["id"],p["type_piece"],p.get("equip_nom",""),p.get("projet_nom",""),p.get("quantite",1),p.get("reference",""),p.get("date_installation",""),p.get("duree_vie_estimee",""),p.get("date_fin_de_vie",""),p["statut"])
             for p in rows(db.execute("SELECT p.*,e.designation AS equip_nom,pr.nom AS projet_nom FROM pieces p JOIN equipements e ON p.equipement_id=e.id JOIN projets pr ON e.projet_id=pr.id ORDER BY pr.nom,e.designation"))])
        buf=io.BytesIO(); wb.save(buf); buf.seek(0)
        return send_file(buf,mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",as_attachment=True,download_name=f"gmao_export_{today()}.xlsx")
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
                except: pass
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
    i=one(db.execute("""SELECT i.*,e.designation AS equip_nom,e.type_technique,e.localisation,e.marque,e.modele,
           p.nom AS projet_nom,p.numero_projet,c.societe AS client_nom,u.nom AS technicien_nom
           FROM interventions i JOIN equipements e ON i.equipement_id=e.id JOIN projets p ON e.projet_id=p.id
           LEFT JOIN clients c ON p.client_id=c.id LEFT JOIN utilisateurs u ON i.technicien_id=u.id WHERE i.id=?""",(iid,)))
    if not i: return jsonify({"error":"Non trouve"}),404
    crs=rows(db.execute("SELECT * FROM comptes_rendus WHERE intervention_id=? ORDER BY created_at",(iid,)))
    for cr in crs:
        try:
            cr["intervenants"]=rows(db.execute("""SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
                FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id WHERE ci.cr_id=?""",(cr["id"],)))
        except: cr["intervenants"]=[]
    def mf(field): return "\n".join([cr.get(field,"") for cr in crs if cr.get(field,"")])
    all_ivs,seen=[],set()
    for cr in crs:
        for iv in cr.get("intervenants",[]):
            k=(iv.get("nom",""),iv.get("date",""))
            if k not in seen: seen.add(k); all_ivs.append(iv)
    iv_names=", ".join(set(iv.get("nom","") for iv in all_ivs if iv.get("nom","")))
    if not iv_names and i.get("technicien_nom"): iv_names=i["technicien_nom"]
    date_iv=(mf("date_intervention") or (i.get("date_realisation") or i.get("date_prevue") or today()))
    date_iv=date_iv.split("\n")[0][:10]
    tr="RAPPORT D'INTERVENTION - DEPANNAGE" if i["type"]=="DEPANNAGE" else "RAPPORT D'INTERVENTION"
    eq=i.get("equip_nom","--")
    if i.get("marque") and i.get("modele"): eq+=f" - {i['marque']} {i['modele']}"
    try:
        pdf=generate_rapport({"titre_rapport":tr,"titre":eq,"client":i.get("client_nom","--"),
            "numero_projet":i.get("numero_projet","--"),"numero_iv":i.get("numero","--"),
            "type_label":i["type"],"date":date_iv,"equipement":eq,"localisation":i.get("localisation","--"),
            "intervenants":iv_names or "--","intervenants_list":all_ivs,
            "observations":mf("observations"),"actions_realisees":mf("actions_realisees"),
            "mesures":mf("mesures"),"recommandations":mf("recommandations"),"conclusion":mf("conclusion")})
    except Exception as e: return jsonify({"error":f"Erreur PDF : {str(e)}"}),500
    fn=f"rapport_{i.get('numero','IV')}_{(i.get('client_nom') or 'SOCOM').replace(' ','_')}.pdf"
    return send_file(io.BytesIO(pdf),mimetype="application/pdf",as_attachment=True,download_name=fn)
