#!/usr/bin/env python3
"""
Diagnostic spécifique pour un MANAGER : est-ce qu'il voit bien ses bons ?
Usage : python3 diagnose_manager.py <manager_id>
"""
import sys, sqlite3

DB_PATH = "/var/www/gmao/gmao.db"

if len(sys.argv) < 2:
    print("Usage: python3 diagnose_manager.py <manager_id>")
    sys.exit(1)

mid = int(sys.argv[1])
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

u = conn.execute("SELECT id, nom, role FROM utilisateurs WHERE id=?", (mid,)).fetchone()
if not u:
    print(f"❌ User {mid} introuvable"); sys.exit(1)
print(f"\n=== Manager: {u['nom']} (id={u['id']}, role={u['role']}) ===\n")

# 1) Projets dont je suis manager
print("1) PROJETS DONT JE SUIS MANAGER")
projs = conn.execute("SELECT id, numero_projet, nom FROM projets WHERE manager_id=?", (mid,)).fetchall()
if projs:
    for p in projs:
        print(f"   - id={p['id']} {p['numero_projet']} - {p['nom']}")
else:
    print("   ❌ AUCUN PROJET — c'est pour ça que tu ne vois pas les bons!")
    print("   → Va dans Paramètres → Projets et assigne-toi comme manager")

# 2) Techniciens de mon équipe (manager_id = mon id)
print("\n2) TECHNICIENS DE MON ÉQUIPE (manager_id=moi)")
techs = conn.execute("SELECT id, nom, role FROM utilisateurs WHERE manager_id=?", (mid,)).fetchall()
if techs:
    for t in techs:
        print(f"   - id={t['id']} {t['nom']} ({t['role']})")
else:
    print("   ❌ AUCUN TECHNICIEN — aucun tech n'a ton id en manager_id")
    print("   → Va dans Paramètres → Utilisateurs et édite les techs pour leur assigner le manager")

# 3) Ce que le manager devrait voir avec la nouvelle logique
print("\n3) BONS VISIBLES PAR CE MANAGER (nouvelle logique)")
rows = conn.execute("""
    SELECT i.id, i.numero, i.statut, i.technicien_id,
           p.nom AS projet_nom, p.manager_id AS proj_mgr,
           u.nom AS tech_nom,
           (SELECT GROUP_CONCAT(u2.nom) FROM intervention_techniciens it 
            JOIN utilisateurs u2 ON it.utilisateur_id=u2.id 
            WHERE it.intervention_id=i.id) AS multi
    FROM interventions i
    JOIN equipements e ON i.equipement_id=e.id
    JOIN projets p ON e.projet_id=p.id
    LEFT JOIN utilisateurs u ON i.technicien_id=u.id
    WHERE (p.manager_id=? 
        OR i.technicien_id=?
        OR i.technicien_id IN (SELECT id FROM utilisateurs WHERE manager_id=?)
        OR EXISTS (SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND 
                   (it.utilisateur_id=? OR it.utilisateur_id IN (SELECT id FROM utilisateurs WHERE manager_id=?))))
      AND i.statut IN ('PLANIFIEE','EN_COURS')
""", (mid, mid, mid, mid, mid)).fetchall()
if rows:
    for r in rows:
        print(f"   - {r['numero']} ({r['statut']}) projet={r['projet_nom']} (mgr={r['proj_mgr']}) tech_principal={r['tech_nom'] or '—'} multi=[{r['multi'] or ''}]")
else:
    print("   (aucun)")

# 4) Qu'est-ce qui manque pour voir BT00028 ?
print("\n4) DÉTAIL BT00028 (ou bon similaire sans tech)")
bt = conn.execute("""
    SELECT i.id, i.numero, i.statut, i.technicien_id, i.equipe_id,
           i.equipement_id, e.designation AS equip, p.id AS proj_id, p.nom AS proj_nom, p.manager_id AS proj_mgr
    FROM interventions i
    JOIN equipements e ON i.equipement_id=e.id
    JOIN projets p ON e.projet_id=p.id
    WHERE i.numero='BT00028'
""").fetchone()
if bt:
    print(f"   - numero={bt['numero']} statut={bt['statut']}")
    print(f"   - tech_principal_id={bt['technicien_id']} equipe_id={bt['equipe_id']}")
    print(f"   - équipement: {bt['equip']}")
    print(f"   - projet: id={bt['proj_id']} '{bt['proj_nom']}' manager_id={bt['proj_mgr']}")
    if bt['proj_mgr'] == mid:
        print(f"   ✅ Le projet T'EST ASSIGNÉ → tu DEVRAIS voir ce bon")
    else:
        print(f"   ❌ Le projet est assigné au manager {bt['proj_mgr']} (pas toi={mid})")
        print(f"   → Édite le projet id={bt['proj_id']} pour te mettre comme manager")
else:
    print("   Pas de bon BT00028 trouvé")

conn.close()
