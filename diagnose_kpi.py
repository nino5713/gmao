#!/usr/bin/env python3
"""
Compare ce que renvoie /api/dashboard (KPI) vs /api/interventions (page Bons)
pour comprendre pourquoi le compteur diffère.

Usage : python3 diagnose_kpi.py <technicien_id>
"""
import sys, sqlite3, os

DB_PATH = "/var/www/gmao/gmao.db"

if len(sys.argv) < 2:
    print("Usage: python3 diagnose_kpi.py <technicien_id>")
    sys.exit(1)

tid = int(sys.argv[1])
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

u = conn.execute("SELECT id, nom, role FROM utilisateurs WHERE id=?", (tid,)).fetchone()
if not u:
    print(f"❌ User {tid} introuvable"); sys.exit(1)
print(f"\n=== Utilisateur: {u['nom']} (role={u['role']}) ===\n")

# 1) Ce que compte le KPI dashboard (kpi.a_planifier + kpi.en_cours)
print("1) CE QUE LE DASHBOARD COMPTE")
print("   (tous les bons PLANIFIEE + EN_COURS, tous confondus)")
dash = conn.execute("""
    SELECT COUNT(*) AS n, statut FROM interventions
    WHERE statut IN ('PLANIFIEE','EN_COURS')
    GROUP BY statut
""").fetchall()
for r in dash:
    print(f"   - {r['statut']}: {r['n']}")

# 2) Ce que voit le tech dans /api/interventions (filtré par role=technicien)
print("\n2) CE QUE LE TECH VOIT DANS /api/interventions")
print("   (filtré par: i.technicien_id=? OU equipe OU intervention_techniciens)")
if u["role"] == "technicien":
    mine = conn.execute("""
        SELECT i.id, i.numero, i.statut, i.technicien_id,
               (SELECT GROUP_CONCAT(it.utilisateur_id)
                FROM intervention_techniciens it WHERE it.intervention_id=i.id) AS tech_ids
        FROM interventions i
        WHERE (i.technicien_id=? 
            OR i.equipe_id IN (SELECT equipe_id FROM equipe_membres WHERE technicien_id=?)
            OR EXISTS (SELECT 1 FROM intervention_techniciens it WHERE it.intervention_id=i.id AND it.utilisateur_id=?))
          AND i.statut NOT IN ('TERMINEE','ANNULEE')
    """, (tid, tid, tid)).fetchall()
else:
    # admin/manager : voit tout
    mine = conn.execute("SELECT i.id, i.numero, i.statut, i.technicien_id, '' AS tech_ids FROM interventions i WHERE i.statut NOT IN ('TERMINEE','ANNULEE')").fetchall()
for r in mine:
    print(f"   - {r['numero']} (id={r['id']}) statut={r['statut']} tech_principal={r['technicien_id']} multi={r['tech_ids']}")
print(f"   Total visible par le tech: {len(mine)}")

# 3) Détail : quel bon pose problème ?
print("\n3) DÉTAIL DE TOUS LES BONS ACTIFS (planifiés + en cours)")
all_actifs = conn.execute("""
    SELECT i.id, i.numero, i.statut, i.technicien_id, i.equipe_id,
           u.nom AS tech_nom,
           (SELECT GROUP_CONCAT(u2.nom)
            FROM intervention_techniciens it JOIN utilisateurs u2 ON it.utilisateur_id=u2.id
            WHERE it.intervention_id=i.id) AS multi_techs
    FROM interventions i
    LEFT JOIN utilisateurs u ON i.technicien_id=u.id
    WHERE i.statut IN ('PLANIFIEE','EN_COURS')
    ORDER BY i.id
""").fetchall()
for r in all_actifs:
    indicator = "  👉 MOI" if (r['technicien_id'] == tid) else ""
    print(f"   - {r['numero']} ({r['statut']}) principal={r['tech_nom'] or '—'} (id={r['technicien_id']}) equipe_id={r['equipe_id']} multi=[{r['multi_techs'] or ''}]{indicator}")

# 4) Vérifier les équipes
print("\n4) ÉQUIPES DU TECHNICIEN")
eqs = conn.execute("SELECT eq.id, eq.nom FROM equipes eq JOIN equipe_membres em ON em.equipe_id=eq.id WHERE em.technicien_id=?", (tid,)).fetchall()
if eqs:
    for e in eqs:
        print(f"   - équipe id={e['id']} nom={e['nom']}")
else:
    print("   (aucune)")

conn.close()
