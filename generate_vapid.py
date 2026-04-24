"""
Script à exécuter UNE SEULE FOIS sur le serveur pour générer les clés VAPID.
Usage :
  pip install pywebpush --break-system-packages
  python3 generate_vapid.py
Les clés générées doivent être copiées dans app.py (VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY).
"""
from py_vapid import Vapid
import base64

v = Vapid()
v.generate_keys()

# Export au format base64url
priv_raw = v.private_key.private_numbers().private_value.to_bytes(32, 'big')
pub_point = v.public_key.public_numbers()
pub_raw = b'\x04' + pub_point.x.to_bytes(32, 'big') + pub_point.y.to_bytes(32, 'big')

priv_b64 = base64.urlsafe_b64encode(priv_raw).decode().rstrip('=')
pub_b64 = base64.urlsafe_b64encode(pub_raw).decode().rstrip('=')

print("# ═══ Copier ces valeurs dans app.py ═══")
print(f'VAPID_PUBLIC_KEY = "{pub_b64}"')
print(f'VAPID_PRIVATE_KEY = "{priv_b64}"')
print(f'VAPID_CLAIM_EMAIL = "mailto:contact@socom.lu"  # à adapter')
