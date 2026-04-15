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
        try:
            db.execute("INSERT INTO mail_log (destinataire,sujet,statut) VALUES (?,?,?)",(to,subj,"ENVOYE"))
            db.commit()
        except: pass
    except Exception as e:
        print(f"[MAIL] {e}")
        try:
            db2=get_db()
            db2.execute("INSERT INTO mail_log (destinataire,sujet,statut,erreur) VALUES (?,?,?,?)",(to,subj,"ERREUR",str(e)))
            db2.commit()
        except: pass

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
                    cr["intervenants"]=rows(db.execute("""
                        SELECT ci.*,COALESCE(u2.nom,ci.nom,'') AS nom
                        FROM cr_intervenants ci LEFT JOIN utilisateurs u2 ON ci.utilisateur_id=u2.id
                        WHERE ci.cr_id=? ORDER BY ci.id""",(cr["id"],)))
                def mf(field): return "\n".join([cr.get(field,"") for cr in crs if cr.get(field,"")])
                all_ivs,seen2=[],set()
                for cr in crs:
                    for iv in cr.get("intervenants",[]):
                        nom2=iv.get("nom","") or ""
                        if not nom2 and iv.get("utilisateur_id"):
                            u2=one(db.execute("SELECT nom FROM utilisateurs WHERE id=?",(iv["utilisateur_id"],)))
                            if u2: nom2=u2["nom"]
                        k2=(nom2,iv.get("date",""))
                        if k2 not in seen2 and nom2:
                            seen2.add(k2)
                            all_ivs.append({"nom":nom2,"date":iv.get("date",""),
                                "heure_debut":iv.get("heure_debut",""),"heure_fin":iv.get("heure_fin",""),
                                "total_heures":iv.get("total_heures",0)})
                tech_nom_r=one(db.execute("SELECT nom FROM utilisateurs WHERE id=?",(r.get("technicien_id","0"),)))
                tech_nom=tech_nom_r["nom"] if tech_nom_r else "--"
                if not all_ivs:
                    for cr in crs:
                        all_ivs.append({"nom":tech_nom,"date":cr.get("date_intervention",""),
                            "heure_debut":"","heure_fin":"","total_heures":cr.get("total_heures",0)})
                date_iv=(mf("date_intervention") or (r.get("date_realisation") or today()))
                date_iv=date_iv.split("\n")[0][:10]
                tr="RAPPORT D'INTERVENTION - DEPANNAGE" if r["type"]=="DEPANNAGE" else "RAPPORT D'INTERVENTION"
                proj2 = one(db.execute("SELECT numero_projet FROM projets WHERE id=(SELECT projet_id FROM equipements WHERE id=?)",(r.get("equipement_id"),)))
                num_proj2 = proj2["numero_projet"] if proj2 and proj2["numero_projet"] else "--"
                pdf_bytes=generate_rapport({"titre_rapport":tr,"titre":r["designation"],"client":r["projet"],
                    "numero_projet":num_proj2,"numero_iv":r["numero"],"type_label":r["type"],"date":date_iv,
                    "equipement":r["designation"],"localisation":"--","intervenants":tech_nom or "--",
                    "intervenants_list":all_ivs,"observations":mf("observations"),
                    "actions_realisees":mf("actions_realisees"),"mesures":mf("mesures"),
                    "recommandations":mf("recommandations"),"conclusion":mf("conclusion")})
                attachments.append((f"Rapport_{r['numero']}.pdf",pdf_bytes))
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
            CHECK(role IN ('admin','manager','technicien','acl')),
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
    td = today()
    # Filtre selon rôle
    role_filter = ""
    role_params = []
    if u["role"] == "technicien":
        # Technicien : uniquement ses bons
        role_filter = " AND (i.technicien_id=? OR i.equipe_id IN (SELECT equipe_id FROM equipe_membres WHERE technicien_id=?))"
        role_params = [u["id"], u["id"]]
    elif u["role"] == "manager":
        # Manager : sous-requête sur equipements pour éviter le JOIN manquant dans KPI
        role_filter = " AND i.equipement_id IN (SELECT e.id FROM equipements e JOIN projets p ON e.projet_id=p.id WHERE p.manager_id=?)"
        role_params = [u["id"]]
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
def request_reset():
    d  = request.json or {}
    email = d.get("email","").strip()
    if not email: return jsonify({"error":"Email requis"}),400
    db = get_db()
    u = one(db.execute("SELECT * FROM utilisateurs WHERE email=? AND actif=1",(email,)))
    if not u:
        # Ne pas révéler si l'email existe ou non
        return jsonify({"ok":True})
    import secrets
    token = secrets.token_urlsafe(32)
    # Stocker le token avec expiration (1 heure)
    expires = (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        db.execute("ALTER TABLE utilisateurs ADD COLUMN reset_token TEXT")
        db.execute("ALTER TABLE utilisateurs ADD COLUMN reset_expires TEXT")
        db.commit()
    except: pass
    db.execute("UPDATE utilisateurs SET reset_token=?,reset_expires=? WHERE id=?",(token,expires,u["id"]))
    db.commit()
    # Envoyer le mail
    base_url = request.headers.get("Origin","http://"+request.host)
    reset_link = f"{base_url}?reset_token={token}"
    body = f"""Bonjour {u['nom']},

Vous avez demandé la réinitialisation de votre mot de passe SOCOM GMAO.

Cliquez sur ce lien pour définir un nouveau mot de passe (valable 1 heure) :
{reset_link}

Si vous n'avez pas fait cette demande, ignorez cet email.

Cordialement,
SOCOM GMAO"""
    send_mail(u["email"],"[GMAO] Réinitialisation de mot de passe",body)
    return jsonify({"ok":True})

@app.route("/api/reset-password/confirm", methods=["POST"])
def confirm_reset():
    d = request.json or {}
    token = d.get("token","")
    new_pw = d.get("password","")
    if not token or not new_pw: return jsonify({"error":"Token et mot de passe requis"}),400
    if len(new_pw) < 6: return jsonify({"error":"Mot de passe trop court (6 caractères minimum)"}),400
    db = get_db()
    u = one(db.execute("SELECT * FROM utilisateurs WHERE reset_token=?",(token,)))
    if not u: return jsonify({"error":"Token invalide"}),400
    # Vérifier expiration
    try:
        expires = datetime.strptime(u["reset_expires"],"%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() > expires:
            return jsonify({"error":"Token expiré, veuillez refaire une demande"}),400
    except: return jsonify({"error":"Token invalide"}),400
    db.execute("UPDATE utilisateurs SET password=?,reset_token=NULL,reset_expires=NULL WHERE id=?",(hp(new_pw),u["id"]))
    db.commit()
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
    d=request.json or {}; db=get_db(); sets,params=[],[]
    for f in ["nom","gsm","couleur","actif"]:
        if f in d: sets.append(f"{f}=?"); params.append(d[f])
    if not sets: return jsonify({"error":"Rien"}),400
    params.append(tid); db.execute(f"UPDATE techniciens_astreinte SET {chr(44).join(sets)} WHERE id=?",params); db.commit()
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
            except: pass
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
        BLUE = colors.HexColor("#0d1b2a")
        ACCENT = colors.HexColor("#00b4d8")
        LIGHT = colors.HexColor("#f8fafc")
        BORDER = colors.HexColor("#e2e8f0")
        buf = io.BytesIO()
        proj_nom = proj.get("nom","") or ""
        proj_loc = (str(proj.get("ville",""))+" "+str(proj.get("code_postal",""))).strip() if proj.get("ville") else ""

        # ═══════════════════════════════════════
        # PAGE DE GARDE
        # ═══════════════════════════════════════
        cv = rl_canvas.Canvas(buf, pagesize=landscape(A4))
        cv.setFillColor(colors.white); cv.rect(0,0,PAGE_W,PAGE_H,fill=1,stroke=0)
        # Arcs déco
        for ch2,ro in [("#0d1b2a",380),("#00b4d8",280),("#ffffff",200),("#0d1b2a",120)]:
            cv.setFillColor(colors.HexColor(ch2))
            p=cv.beginPath(); p.moveTo(PAGE_W,PAGE_H)
            p.arcTo(PAGE_W-ro,PAGE_H-ro,PAGE_W+20,PAGE_H+20,180,90)
            p.lineTo(PAGE_W,PAGE_H); p.close(); cv.drawPath(p,fill=1,stroke=0)
        cv.setFillColor(colors.HexColor("#00b4d8")); cv.setFillAlpha(0.08)
        p5=cv.beginPath(); p5.moveTo(0,0); p5.arcTo(-20,-20,220,220,0,90); p5.lineTo(0,0); p5.close()
        cv.drawPath(p5,fill=1,stroke=0); cv.setFillAlpha(1)
        # Illustration dashboard matplotlib
        fig=plt.figure(figsize=(9,6),facecolor="white")
        ax=fig.add_axes([0,0,1,1]); ax.set_xlim(0,16); ax.set_ylim(0,10); ax.set_facecolor("white"); ax.axis("off")
        ax.add_patch(FancyBboxPatch((0.3,0.5),15.2,9.0,boxstyle="round,pad=0.2",facecolor="#f8fafc",edgecolor="#e2e8f0",lw=1.5))
        ax.add_patch(FancyBboxPatch((0.3,8.5),15.2,1.0,boxstyle="round,pad=0.1",facecolor="#0d1b2a",edgecolor="none"))
        ax.text(8,9.0,"TABLEAU DE BORD ENERGETIQUE",ha="center",va="center",fontsize=10,color="white",fontweight="bold")
        for xi2,c3 in [(13.8,"#ef4444"),(14.3,"#f59e0b"),(14.8,"#22c55e")]:
            ax.add_patch(Circle((xi2,9.0),0.12,facecolor=c3,edgecolor="none"))
        kpi2=[("ELECTRICITE","284 kWh","-8%","#3b82f6","#eff6ff"),("EAU","42 m3","+2%","#06b6d4","#ecfeff"),("GAZ","18.9 MWh","-12%","#f97316","#fff7ed"),("DJU FROID","318 J","-5%","#8b5cf6","#f5f3ff")]
        for i2,(t2,v2,d2_,c3,bg2) in enumerate(kpi2):
            kx2=0.6+i2*3.8
            ax.add_patch(FancyBboxPatch((kx2,6.8),3.4,1.5,boxstyle="round,pad=0.12",facecolor=bg2,edgecolor=c3,lw=1.5))
            ax.text(kx2+0.2,8.1,t2,fontsize=6.5,color="#64748b",fontweight="bold",va="center")
            ax.text(kx2+0.2,7.15,v2,fontsize=11,color="#0d1b2a",fontweight="bold",va="center")
            dc2="#22c55e" if "-" in d2_ else "#ef4444"
            ax.text(kx2+2.2,7.15,d2_,fontsize=8,color=dc2,fontweight="bold",va="center")
            ax.add_patch(FancyBboxPatch((kx2+0.2,6.9),2.8,0.15,boxstyle="square,pad=0",facecolor="#e2e8f0",edgecolor="none"))
            ax.add_patch(FancyBboxPatch((kx2+0.2,6.9),2.8*[0.72,0.45,0.88,0.62][i2],0.15,boxstyle="square,pad=0",facecolor=c3,edgecolor="none"))
        ax.add_patch(FancyBboxPatch((0.5,1.0),9.2,5.5,boxstyle="round,pad=0.1",facecolor="white",edgecolor="#e2e8f0",lw=1))
        ax.text(5.1,6.25,"Consommations corrigees - Comparaison",ha="center",fontsize=7.5,color="#334155",fontweight="bold")
        mn2=np.arange(12); d25_=np.array([1250,1180,980,820,650,520,490,510,680,920,1100,1280])
        d26_=np.array([1180,1050,920,780,610,480,np.nan,np.nan,np.nan,np.nan,np.nan,np.nan])
        def ny2(v): return 1.3+(v-400)/(1350-400)*4.8
        xs2=0.7+mn2*0.75; y25_=ny2(d25_)
        ax.fill_between(xs2,1.3,y25_,alpha=0.08,color="#0d1b2a"); ax.plot(xs2,y25_,"-",color="#0d1b2a",lw=2,zorder=4)
        mask2=~np.isnan(d26_); y26_=ny2(np.where(mask2,d26_,np.nan))
        ax.fill_between(xs2[mask2],1.3,y26_[mask2],alpha=0.15,color="#00b4d8"); ax.plot(xs2[mask2],y26_[mask2],"o-",color="#00b4d8",lw=2.5,ms=5,zorder=4)
        for gv2 in [1.3,2.5,3.7,4.9,6.1]: ax.plot([0.7,9.5],[gv2,gv2],color="#f1f5f9",lw=0.8,zorder=1)
        ml2=["J","F","M","A","M","J","J","A","S","O","N","D"]
        for i2,xl2 in enumerate(xs2): ax.text(xl2,1.05,ml2[i2],ha="center",fontsize=6.5,color="#94a3b8")
        ax.add_patch(FancyBboxPatch((10.0,1.0),5.2,3.0,boxstyle="round,pad=0.1",facecolor="white",edgecolor="#e2e8f0",lw=1))
        ax.text(12.6,3.75,"Mix energetique",ha="center",fontsize=7,color="#334155",fontweight="bold")
        start2=90
        for sz2,pc2 in zip([42,28,18,12],["#3b82f6","#00b4d8","#f97316","#22c55e"]):
            end2=start2-sz2*3.6
            ax.add_patch(Wedge((12.6,2.3),0.9,end2,start2,facecolor=pc2,edgecolor="white",lw=2,alpha=0.85))
            ma2=np.radians((start2+end2)/2)
            ax.text(12.6+0.62*np.cos(ma2),2.3+0.62*np.sin(ma2),str(sz2)+"%",ha="center",va="center",fontsize=6.5,color="white",fontweight="bold")
            start2=end2
        ib=io.BytesIO(); plt.savefig(ib,format="png",dpi=150,bbox_inches="tight",facecolor="white",edgecolor="none"); ib.seek(0); plt.close(fig)
        cv.drawImage(ImageReader(ib),PAGE_W*0.36,PAGE_H*0.08,width=PAGE_W*0.60,height=PAGE_H*0.84,preserveAspectRatio=True,anchor="c")
        # Logo SOCOM
        try:
            html_c=open("/var/www/gmao/index.html").read()[:15000]
            m3=_re.search(r'src="data:image/png;base64,([^"]+)"',html_c)
            if m3:
                limg=ImageReader(io.BytesIO(base64.b64decode(m3.group(1))))
                lw3=175; lh3=lw3*148/650
                cv.drawImage(limg,36,PAGE_H-lh3-24,width=lw3,height=lh3)
        except: pass
        # Textes page de garde
        cv.setFillColor(colors.HexColor("#00b4d8")); cv.setFont("Helvetica-Bold",8)
        cv.drawString(40,PAGE_H*0.60,"RAPPORT ENERGETIQUE")
        cv.setLineWidth(2); cv.setStrokeColor(colors.HexColor("#00b4d8")); cv.line(40,PAGE_H*0.585,168,PAGE_H*0.585)
        cv.setFillColor(colors.HexColor("#0d1b2a")); cv.setFont("Helvetica-Bold",30)
        cv.drawString(38,PAGE_H*0.52,"SUIVI"); cv.drawString(38,PAGE_H*0.44,"ENERGETIQUE")
        cv.setFillColor(colors.HexColor("#64748b")); cv.setFont("Helvetica",10)
        cv.drawString(40,PAGE_H*0.385,"Analyse & Comparaison annuelle")
        cv.setStrokeColor(colors.HexColor("#e2e8f0")); cv.setLineWidth(1); cv.line(40,PAGE_H*0.355,PAGE_W*0.33,PAGE_H*0.355)
        cv.setFillColor(colors.HexColor("#0d1b2a")); cv.setFont("Helvetica-Bold",16); cv.drawString(40,PAGE_H*0.315,proj_nom)
        cv.setFillColor(colors.HexColor("#64748b")); cv.setFont("Helvetica",10)
        if proj_loc: cv.drawString(40,PAGE_H*0.275,proj_loc)
        cv.drawString(40,PAGE_H*0.235,"Annee "+str(annee-1)+" vs "+str(annee))
        cv.setFillColor(colors.HexColor("#f8fafc")); cv.rect(0,0,PAGE_W,24,fill=1,stroke=0)
        cv.setFillColor(colors.HexColor("#00b4d8")); cv.rect(0,0,4,24,fill=1,stroke=0)
        cv.setFillColor(colors.HexColor("#64748b")); cv.setFont("Helvetica",7.5)
        cv.drawString(14,8,"SOCOM - Maintenance Multi-Techniques")
        cv.drawString(PAGE_W-155,8,"Genere le "+datetime.now().strftime("%d/%m/%Y"))
        cv.showPage()

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
            # Charger données pour les graphiques
            equips_g=rows(db.execute("SELECT e.* FROM equipements e WHERE e.projet_id=? AND e.type_technique='Compteurs'",(projet_id,)))
            # Préparer données compteurs
            cpt_data={}  # {cpt_id: [{label,value}]}
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
                                lbl=dp4s[:7]  # YYYY-MM
                                cpt_data[cpt["id"]]["pts"].append({"label":lbl,"value":val})
                            except: pass
            COLORS_G=["#3b82f6","#ef4444","#22c55e","#f59e0b","#8b5cf6","#14b8a6","#f97316"]
            for g5 in graphiques:
                try:
                    series5=_json2.loads(g5.get("series","[]"))
                    if not series5: continue
                    fig5,ax5=plt.subplots(figsize=(11,4.5),facecolor="white")
                    ax5.set_facecolor("#f8fafc")
                    has_data=False
                    # Axes
                    types5=[s.get("type","histogramme") for s in series5]
                    has_dual=len(set(types5))>1 and len(series5)>1
                    ax5_r=ax5.twinx() if has_dual else None
                    for si5,serie5 in enumerate(series5):
                        cid5=serie5.get("compteur_id")
                        col5=COLORS_G[si5%len(COLORS_G)]
                        ax_use=ax5_r if (has_dual and si5>0) else ax5
                        pts5=[]
                        if cid5 and cid5 in cpt_data:
                            pts5=cpt_data[cid5]["pts"]
                        elif str(cid5) in [str(k) for k in cpt_data.keys()]:
                            cid5_int=next(k for k in cpt_data.keys() if str(k)==str(cid5))
                            pts5=cpt_data[cid5_int]["pts"]
                        if not pts5: continue
                        lbls5=[p["label"] for p in pts5 if p["value"] is not None]
                        vals5=[p["value"] for p in pts5 if p["value"] is not None]
                        if not lbls5: continue
                        lbl5=str(serie5.get("label","") or serie5.get("nom_compteur","") or "Serie")
                        t5=serie5.get("type","histogramme")
                        if t5=="courbe":
                            ax_use.plot(range(len(lbls5)),vals5,"o-",color=col5,lw=2,ms=5,label=lbl5)
                        elif t5=="histogramme_empile":
                            ax_use.bar(range(len(lbls5)),vals5,color=col5,alpha=0.75,label=lbl5)
                        else:
                            ax_use.bar(range(len(lbls5)),vals5,color=col5,alpha=0.75,label=lbl5)
                        ax_use.set_xticks(range(len(lbls5))); ax_use.set_xticklabels(lbls5,rotation=30,ha="right",fontsize=7)
                        has_data=True
                    if has_data:
                        ax5.set_title(str(g5.get("titre","Graphique")),fontsize=10,fontweight="bold",color="#0d1b2a",pad=8)
                        ax5.grid(axis="y",alpha=0.3,linestyle="--"); ax5.spines["top"].set_visible(False)
                        handles5,labels5=ax5.get_legend_handles_labels()
                        if ax5_r:
                            h2,l2=ax5_r.get_legend_handles_labels()
                            handles5+=h2; labels5+=l2
                            ax5_r.spines["top"].set_visible(False)
                        if handles5: ax5.legend(handles5,labels5,fontsize=8,loc="upper right",framealpha=0.9)
                        plt.tight_layout()
                        gi=io.BytesIO(); plt.savefig(gi,format="png",dpi=130,bbox_inches="tight",facecolor="white"); gi.seek(0)
                        story_p.append(Paragraph(str(g5.get("titre","")),section_s))
                        story_p.append(RLImage(gi,width=24*cm,height=10*cm))
                        story_p.append(Spacer(1,10))
                    plt.close(fig5)
                except Exception as eg: pass
            story_p.append(PageBreak())

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
            doc=SimpleDocTemplate(buf,pagesize=landscape(A4),leftMargin=1.2*cm,rightMargin=1.2*cm,topMargin=1.8*cm,bottomMargin=1.2*cm)
            doc.build(story_p,onFirstPage=on_pg,onLaterPages=on_pg)

        buf.seek(0)
        fname="rapport_energie_"+proj_nom.replace(" ","_")+"_"+str(annee)+".pdf"
        return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=fname)

    except Exception as e:
        import traceback
        return jsonify({"error":str(e),"trace":traceback.format_exc()}),500


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
                d.get("description",""),d.get("date_debut") or None,d.get("date_fin") or None,d.get("statut","EN_COURS"),d.get("ville",""),d.get("code_postal","")))
    db.commit(); return jsonify({"id":db.execute("SELECT last_insert_rowid()").fetchone()[0]}),201


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
    for f in ["nom","client_id","manager_id","description","date_debut","date_fin","statut","numero_projet","ville","code_postal"]:
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
    for f in ["designation","type_technique","projet_id","localisation","marque","modele","puissance","numero_serie","in_out","date_mise_en_service","statut","technique_id","notes"]:
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
                except: pass
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
    return jsonify(rows(db.execute(sql+" ORDER BY CASE WHEN i.date_prevue IS NULL THEN 1 ELSE 0 END, i.date_prevue ASC, i.created_at DESC",params)))

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
    db=get_db(); num=next_numero(db,"BT","interventions","numero")
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
        cr["releves"]=rows(db.execute("SELECT r.*,c.nom AS compteur_nom,c.numero,c.unite,c.localisation,ct.nom AS type_nom FROM releves_compteurs r JOIN compteurs c ON r.compteur_id=c.id LEFT JOIN compteur_types ct ON c.type_id=ct.id WHERE r.cr_id=? ORDER BY c.nom",(cr["id"],)))
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
    cr_num = next_numero(db,"CR","comptes_rendus","numero") if "numero" in [r[1] for r in db.execute("PRAGMA table_info(comptes_rendus)").fetchall()] else None
    if cr_num:
        db.execute("INSERT INTO comptes_rendus (intervention_id,date_intervention,observations,actions_realisees,mesures,recommandations,conclusion,total_heures,numero) VALUES (?,?,?,?,?,?,?,?,?)",
                   (iid,d.get("date_intervention") or None,d.get("observations",""),d.get("actions_realisees",""),d.get("mesures",""),d.get("recommandations",""),d.get("conclusion",""),th,cr_num))
    else:
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
        cr["intervenants"]=rows(db.execute("""
            SELECT ci.*,COALESCE(u.nom,ci.nom,'') AS nom
            FROM cr_intervenants ci LEFT JOIN utilisateurs u ON ci.utilisateur_id=u.id
            WHERE ci.cr_id=? ORDER BY ci.id""",(cr["id"],)))
    def mf(field): return "\n".join([cr.get(field,"") for cr in crs if cr.get(field,"")])
    # Construire liste intervenants depuis cr_intervenants
    all_ivs,seen=[],set()
    for cr in crs:
        for iv in cr.get("intervenants",[]):
            nom = iv.get("nom","") or ""
            if not nom and iv.get("utilisateur_id"):
                u = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?",(iv["utilisateur_id"],)))
                if u: nom = u["nom"]
            k=(nom, iv.get("date",""))
            if k not in seen and nom:
                seen.add(k)
                all_ivs.append({
                    "nom": nom,
                    "date": iv.get("date",""),
                    "heure_debut": iv.get("heure_debut",""),
                    "heure_fin": iv.get("heure_fin",""),
                    "total_heures": iv.get("total_heures",0)
                })
    # Fallback sur technicien si pas d intervenants
    if not all_ivs and i.get("technicien_nom"):
        for cr in crs:
            all_ivs.append({"nom":i["technicien_nom"],"date":cr.get("date_intervention",""),
                "heure_debut":"","heure_fin":"","total_heures":cr.get("total_heures",0)})
    iv_names=", ".join(set(iv["nom"] for iv in all_ivs)) if all_ivs else i.get("technicien_nom","--")
    date_iv=(mf("date_intervention") or (i.get("date_realisation") or i.get("date_prevue") or today()))
    date_iv=date_iv.split("\n")[0][:10]
    tr="RAPPORT D'INTERVENTION - DEPANNAGE" if i["type"]=="DEPANNAGE" else "RAPPORT D'INTERVENTION"
    eq=i.get("equip_nom","--")
    if i.get("marque") and i.get("modele"): eq+=f" - {i['marque']} {i['modele']}"
    # Récupérer le numéro de projet et le technicien
    proj = one(db.execute("SELECT numero_projet FROM projets WHERE id=(SELECT projet_id FROM equipements WHERE id=?)",(i["equipement_id"],)))
    num_projet = proj["numero_projet"] if proj and proj["numero_projet"] else "--"
    tech_nom = i.get("technicien_nom","")
    if not tech_nom and i.get("technicien_id"):
        t = one(db.execute("SELECT nom FROM utilisateurs WHERE id=?",(i["technicien_id"],)))
        if t: tech_nom = t["nom"]
    iv_names = tech_nom or "--"
    try:
        pdf=generate_rapport({"titre_rapport":tr,"titre":eq,"client":i.get("client_nom","--"),
            "numero_projet":num_projet,"numero_iv":i.get("numero","--"),
            "type_label":i["type"],"date":date_iv,"equipement":eq,"localisation":i.get("localisation","--"),
            "intervenants":iv_names,"intervenants_list":all_ivs,
            "observations":mf("observations"),"actions_realisees":mf("actions_realisees"),
            "mesures":mf("mesures"),"recommandations":mf("recommandations"),"conclusion":mf("conclusion")})
    except Exception as e: return jsonify({"error":f"Erreur PDF : {str(e)}"}),500
    fn=f"Rapport_{i.get('numero','BT00000')}_{(i.get('client_nom') or 'SOCOM').replace(' ','_')}.pdf"
    return send_file(io.BytesIO(pdf),mimetype="application/pdf",as_attachment=True,download_name=fn)
