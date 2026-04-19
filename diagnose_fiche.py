#!/usr/bin/env python3
"""
Script de diagnostic à lancer sur le serveur pour vérifier pourquoi
le matricule/manager n'apparaissent pas dans la fiche de pointage.

Usage : cd /var/www/gmao && python3 diagnose_fiche.py <technicien_id>
"""
import sys, sqlite3, os

DB_PATH = os.environ.get("GMAO_DB", "/var/www/gmao/gmao.db")

if len(sys.argv) < 2:
    print("Usage: python3 diagnose_fiche.py <technicien_id>")
    print("\nListe des techniciens:")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    for r in conn.execute("SELECT id, nom, role FROM utilisateurs WHERE role='technicien' ORDER BY nom"):
        print(f"  id={r['id']:3d}  {r['nom']}")
    sys.exit(1)

tid = int(sys.argv[1])
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# 1. Vérifier colonnes
print("=" * 60)
print("1. COLONNES DE LA TABLE utilisateurs")
print("=" * 60)
cols = conn.execute("PRAGMA table_info(utilisateurs)").fetchall()
col_names = [c[1] for c in cols]
print(f"Colonnes: {col_names}")
if "matricule" not in col_names:
    print("❌ COLONNE 'matricule' MANQUANTE - la migration n'est pas passée")
else:
    print("✓ Colonne 'matricule' présente")
if "manager_id" not in col_names:
    print("❌ COLONNE 'manager_id' MANQUANTE - la migration n'est pas passée")
else:
    print("✓ Colonne 'manager_id' présente")

# 2. Données du technicien
print()
print("=" * 60)
print(f"2. DONNÉES DU TECHNICIEN id={tid}")
print("=" * 60)
u = conn.execute("SELECT * FROM utilisateurs WHERE id=?", (tid,)).fetchone()
if not u:
    print(f"❌ Technicien {tid} introuvable")
    sys.exit(1)
for k in u.keys():
    val = u[k]
    print(f"  {k}: {repr(val)}  (type={type(val).__name__})")

# 3. Vérifier manager
if u["manager_id"] if "manager_id" in u.keys() else None:
    print()
    print("=" * 60)
    print("3. MANAGER DU TECHNICIEN")
    print("=" * 60)
    mgr = conn.execute("SELECT * FROM utilisateurs WHERE id=?", (u["manager_id"],)).fetchone()
    if mgr:
        print(f"  manager_id={u['manager_id']} → {mgr['nom']} ({mgr['role']})")
    else:
        print(f"  ❌ manager_id={u['manager_id']} mais utilisateur introuvable")
else:
    print()
    print("❌ Pas de manager_id défini pour ce technicien")
    print("   → Va dans Paramètres → Utilisateurs → Édite le technicien → Sélectionne un manager")

conn.close()
