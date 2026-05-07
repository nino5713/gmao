"""
Générateur de rapport d'intervention PDF (SOCOM).
Structure validée en session du 22/04/2026 : 
- En-tête sobre (logo SOCOM haut gauche + trait bleu)
- Titre dynamique (MAINTENANCE ou DÉPANNAGE)
- Logo sécurité PPSS + EPI (centré)
- Informations générales
- Équipement concerné
- Descriptif (depuis champ description du bon)
- Comptes-rendus d'intervention (1 bloc/CR, avec observations + tableau intervenants)
- Signatures

Utilisation :
    from rapport_pdf import generate_rapport
    pdf_bytes = generate_rapport({
        "type_label": "DEPANNAGE",           # ou "MAINTENANCE"
        "numero_iv": "BC00042",
        "date": "21/04/2026",
        "client": "ARCELOR MITTAL LUXEMBOURG S.A.",
        "numero_projet": "P28478",
        "projet_nom": "ARCELOR",
        "equipement": "CTA Atelier B",
        "marque_modele": "Daikin — UATYA-120",
        "localisation": "Bâtiment production",
        "technique": "CVC",
        "intervenants": "David SALMON",      # principal, pour la synthèse
        "description": "Texte saisi à la création du bon",
        "comptes_rendus": [                  # liste structurée
            {
                "date": "21/04/2026",
                "observations": "HTML autorisé <b>...</b>",
                "intervenants": [
                    {"nom": "...", "date": "...", "heure_debut": "...",
                     "heure_fin": "...", "total_heures": 3.25}
                ]
            },
            ...
        ]
    })
"""
import io, os, json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, KeepTogether, PageBreak, KeepInFrame
)

# ──────────────────────────────────────────────────────────────
# Palette SOCOM
# ──────────────────────────────────────────────────────────────
ACCENT = colors.HexColor('#1E3A8A')   # bleu principal
LIGHT  = colors.HexColor('#EFF6FF')   # bleu très clair (fond)
BORDER = colors.HexColor('#CBD5E1')   # gris bordures
TEXT   = colors.HexColor('#0F172A')   # texte principal
MUTED  = colors.HexColor('#64748B')   # texte secondaire

# ──────────────────────────────────────────────────────────────
# Chemins des logos (à côté du fichier Python)
# ──────────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
LOGO_SOCOM_MENU = os.path.join(HERE, 'socom_menu_logo.png')   # logo petit pour en-tête
LOGO_SECU       = os.path.join(HERE, 'logo_rapports.png')      # logo PPSS+EPI combiné
# Compatibilité : si le logo bleu historique existe, on l'utilise pour l'en-tête
LOGO_SOCOM_ALT  = os.path.join(HERE, 'socom_logo.png')


def _pick_logo():
    """Choisit le premier logo SOCOM disponible."""
    for p in (LOGO_SOCOM_MENU, LOGO_SOCOM_ALT):
        if os.path.exists(p):
            return p
    return None


def _format_heures(h):
    """Convertit heures décimales en format Xh YYmin.
    3.25 → '3h 15min' ; 1.0 → '1h' ; 0 → '—'.
    """
    try:
        h = float(h or 0)
        if h <= 0:
            return "—"
        heures = int(h)
        minutes = int(round((h - heures) * 60))
        if minutes == 0:
            return f"{heures}h"
        return f"{heures}h {minutes:02d}min"
    except Exception:
        return "—"


# ══════════════════════════════════════════════════════════════════
# v218.81 : RENDU DE LA PAGE DE GARDE PERSONNALISÉE (mode maintenance)
# ══════════════════════════════════════════════════════════════════
def _resolve_field_value(field, data):
    """Résout la valeur d'un champ dynamique à partir des data du rapport."""
    field_map = {
        'client': data.get('client', '—') or '—',
        'projet': _format_projet(data),
        'numero_iv': data.get('numero_iv', '—') or '—',
        'date': data.get('date', '—') or '—',
        'technicien': data.get('intervenants', '—') or '—',
        'equipement': data.get('equipement', '—') or '—',
        'localisation': data.get('localisation', '—') or '—',
        'technique': data.get('technique', '—') or '—',
        'sous_type': data.get('sous_type', '—') or '—',
    }
    return str(field_map.get(field, '—') or '—')


def _format_projet(data):
    numero_projet = (data.get('numero_projet', '') or '').strip()
    projet_nom = (data.get('projet_nom', '') or '').strip()
    if numero_projet and numero_projet != '—' and projet_nom:
        return f"{numero_projet} — {projet_nom}"
    if numero_projet and numero_projet != '—':
        return numero_projet
    if projet_nom:
        return projet_nom
    return '—'


_FIELD_LABELS = {
    'client': 'Client',
    'projet': 'Projet',
    'numero_iv': 'N° du bon',
    'date': 'Date',
    'technicien': 'Technicien',
    'equipement': 'Équipement',
    'localisation': 'Localisation',
    'technique': 'Technique',
    'sous_type': 'Sous-type',
}


def _interpolate(text, data):
    """Remplace les placeholders {champ} dans text par les valeurs des data."""
    if not text or '{' not in text:
        return text
    result = text
    import re as _re
    for m in _re.findall(r'\{([a-z_]+)\}', text):
        val = _resolve_field_value(m, data)
        result = result.replace('{'+m+'}', val)
    return result


def _render_cover_blocks(blocks, data, styles):
    """Convertit une liste de blocs (config) en éléments reportlab pour la story.
    Retourne une liste à étendre dans story.
    blocks : liste de dicts comme :
      {"type":"title", "text":"...", "font_size":24, "color":"#1E3A8A", "align":"center", "bold":True}
    """
    elements = []
    align_map = {'left': 0, 'center': 1, 'right': 2}
    for b in blocks or []:
        try:
            t = b.get('type')
            if t == 'spacer':
                h = float(b.get('height_cm') or 0.5)
                elements.append(Spacer(1, h*cm))
            elif t == 'separator':
                # Ligne horizontale via une table 1×1 avec une bordure haut
                color = b.get('color', '#CBD5E1')
                thickness = float(b.get('thickness') or 0.5)
                tab = Table([['']], colWidths=[17*cm])
                tab.setStyle(TableStyle([
                    ('LINEABOVE', (0, 0), (-1, -1), thickness, colors.HexColor(color)),
                ]))
                elements.append(tab)
            elif t == 'title' or t == 'subtitle':
                text = _interpolate(b.get('text') or '', data)
                if not text.strip(): continue
                font_size = int(b.get('font_size') or (24 if t == 'title' else 18))
                color_hex = b.get('color') or '#1E3A8A'
                align = align_map.get((b.get('align') or 'center').lower(), 1)
                bold = bool(b.get('bold', True))
                if bold: text = f'<b>{text}</b>'
                style = ParagraphStyle(
                    f'_cover_{t}', fontSize=font_size,
                    textColor=colors.HexColor(color_hex),
                    alignment=align, spaceAfter=6, leading=int(font_size*1.25)
                )
                elements.append(Paragraph(text, style))
            elif t == 'text':
                text = _interpolate(b.get('text') or '', data)
                if not text.strip(): continue
                font_size = int(b.get('font_size') or 11)
                color_hex = b.get('color') or '#0F172A'
                align = align_map.get((b.get('align') or 'left').lower(), 0)
                style = ParagraphStyle(
                    '_cover_text', fontSize=font_size,
                    textColor=colors.HexColor(color_hex),
                    alignment=align, spaceAfter=4, leading=int(font_size*1.3)
                )
                elements.append(Paragraph(text, style))
            elif t == 'image':
                # Si use_projet_logo coché, on prend le projet_logo_path des data
                img_path = ''
                if b.get('use_projet_logo'):
                    img_path = (data.get('projet_logo_path') or '').strip()
                else:
                    rel = (b.get('path') or '').strip()
                    if rel:
                        # Chemin relatif au BASE_DIR de l'app
                        img_path = os.path.join(HERE, rel)
                        if not os.path.exists(img_path):
                            # Essayer un chemin absolu
                            img_path = rel if os.path.exists(rel) else ''
                if not img_path or not os.path.exists(img_path):
                    continue
                width_cm = float(b.get('width_cm') or 8.0)
                align = (b.get('align') or 'center').upper()
                try:
                    img = Image(img_path, width=width_cm*cm, height=width_cm*0.625*cm,
                                kind='proportional')
                    tab = Table([[img]], colWidths=[17*cm])
                    tab.setStyle(TableStyle([
                        ('ALIGN', (0, 0), (-1, -1), align),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('TOPPADDING', (0, 0), (-1, -1), 0),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                    ]))
                    elements.append(tab)
                except Exception:
                    pass
            elif t == 'info_box':
                fields = b.get('fields') or []
                title = b.get('title') or 'INFORMATIONS GÉNÉRALES'
                if not fields: continue
                rows_d = []
                label_style = ParagraphStyle(
                    '_cover_lbl', fontSize=9, textColor=MUTED, leading=12)
                value_style = ParagraphStyle(
                    '_cover_val', fontSize=10, textColor=TEXT, leading=12)
                for f in fields:
                    label = _FIELD_LABELS.get(f, f.title())
                    value = _resolve_field_value(f, data)
                    rows_d.append([
                        Paragraph(label.upper(), label_style),
                        Paragraph(str(value), value_style),
                    ])
                box = Table(rows_d, colWidths=[5*cm, 12*cm])
                box.setStyle(TableStyle([
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
                ]))
                title_style = ParagraphStyle(
                    '_cover_title', fontSize=10, textColor=ACCENT,
                    spaceAfter=4, leading=14)
                elements.append(KeepTogether([
                    Paragraph(f'<b>{title}</b>', title_style),
                    box,
                ]))
            elif t == 'gamme_maintenance':
                # v218.84 : tableau de la gamme de maintenance (opérations cochées/non cochées)
                gamme_ops_list = data.get('gamme_operations') or []
                has_ops = any(g.get('operations') for g in gamme_ops_list)
                if not has_ops:
                    continue
                title = b.get('title') or 'OPÉRATIONS DE LA GAMME DE MAINTENANCE'
                def _xml_esc_g(s):
                    return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                h_normal = ParagraphStyle('_cover_op', fontSize=9, textColor=TEXT, leading=12)
                check_rows = []
                for g in gamme_ops_list:
                    ops = g.get('operations') or []
                    if not ops: continue
                    if len(gamme_ops_list) > 1 and g.get('gamme_nom'):
                        check_rows.append([
                            Paragraph(f'<font color="#1E3A8A"><b>{_xml_esc_g(g["gamme_nom"])}</b></font>', h_normal),
                        ])
                    for op in ops:
                        if isinstance(op, dict):
                            desc = op.get('description','') or ''
                            done = op.get('done', False)
                        else:
                            desc = str(op); done = False
                        if done:
                            check_rows.append([
                                Paragraph(f'<font name="Helvetica-Bold" size="13" color="#10B981">&#10003;</font>&nbsp;&nbsp;{_xml_esc_g(desc)}', h_normal)
                            ])
                        else:
                            check_rows.append([
                                Paragraph(f'<font size="13">&nbsp;&nbsp;&nbsp;</font>&nbsp;&nbsp;{_xml_esc_g(desc)}', h_normal)
                            ])
                if check_rows:
                    title_style = ParagraphStyle('_cover_gamme_title', fontSize=10, textColor=ACCENT, spaceAfter=4, leading=14)
                    tab = Table(check_rows, colWidths=[17*cm])
                    tab.setStyle(TableStyle([
                        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                        ('LEFTPADDING', (0, 0), (-1, -1), 10),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('LINEBELOW', (0, 0), (-1, -2), 0.3, LIGHT),
                    ]))
                    elements.append(Paragraph(f'<b>{title}</b>', title_style))
                    elements.append(tab)
            elif t == 'observations':
                # v218.84 : observations du compte-rendu (premier CR)
                cr_list = data.get('comptes_rendus') or []
                if not cr_list:
                    continue
                first_cr = cr_list[0]
                obs_text = (first_cr.get('observations') or '').strip()
                if not obs_text:
                    continue
                title = b.get('title') or 'OBSERVATIONS'
                def _xml_esc_obs(s):
                    return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                title_style = ParagraphStyle('_cover_obs_title', fontSize=10, textColor=ACCENT, spaceAfter=4, leading=14)
                obs_para = Paragraph(
                    _xml_esc_obs(obs_text).replace('\n', '<br/>'),
                    ParagraphStyle('_cover_obs', fontSize=10, leading=13,
                                   textColor=colors.HexColor("#0f172a"))
                )
                obs_table = Table([[obs_para]], colWidths=[17*cm])
                obs_table.setStyle(TableStyle([
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
                    ('LEFTPADDING', (0, 0), (-1, -1), 12),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ]))
                elements.append(Paragraph(f'<b>{title}</b>', title_style))
                elements.append(obs_table)
        except Exception as e:
            # Un bloc cassé ne doit pas casser le PDF entier
            try:
                import logging
                logging.error(f"[cover-blocks] Bloc ignoré ({b.get('type')}) : {e}")
            except Exception:
                pass
            continue
    return elements


def _hf_resolve_field(field, data, doc):
    """Résout un champ dynamique dans le contexte header/footer (inclut page, total_pages, etc.)."""
    if field == 'page': return str(getattr(doc, 'page', 1))
    if field == 'total_pages': return str(getattr(doc, '_total_pages', '?'))
    if field == 'nom_societe': return data.get('societe_nom', '') or ''
    if field == 'date_generation':
        try:
            return datetime.now().strftime('%d/%m/%Y')
        except Exception:
            return ''
    return _resolve_field_value(field, data)


def _hf_interpolate(text, data, doc):
    """Comme _interpolate mais gère aussi les champs de header/footer."""
    if not text or '{' not in text:
        return text
    result = text
    import re as _re
    for m in _re.findall(r'\{([a-z_]+)\}', text):
        val = _hf_resolve_field(m, data, doc)
        result = result.replace('{'+m+'}', val)
    return result


def _draw_hf_blocks(canvas, doc, blocks, data, area):
    """Dessine une liste de blocs header/footer dans la zone donnée.
    area = {'x': cm, 'y': cm (bas de la zone), 'w': cm, 'h': cm} en points reportlab.
    Les blocs supportés : row (3 colonnes left/center/right), text, image, spacer, separator.
    """
    if not blocks: return
    W, H = A4
    x_left = area['x']
    x_right = area['x'] + area['w']
    x_center = area['x'] + area['w']/2
    # On rendu de bas en haut (pour footer) ou de haut en bas (pour header)
    # Stratégie simple : on calcule le total des hauteurs pour positionner correctement.
    # Pour rester simple, on utilise une "ligne courante" qu'on décrémente du haut.
    # Header: rendu top-down. Footer: rendu top-down aussi mais zone basse.
    cur_y = area['y'] + area['h']  # haut de la zone

    for b in blocks:
        if not isinstance(b, dict): continue
        try:
            t = b.get('type')
            if t == 'spacer':
                hcm = float(b.get('height_cm') or 0.2)
                cur_y -= hcm * cm
            elif t == 'separator':
                col = b.get('color') or '#1E3A8A'
                th = float(b.get('thickness') or 0.5)
                canvas.saveState()
                canvas.setStrokeColor(colors.HexColor(col))
                canvas.setLineWidth(th)
                cur_y -= 2  # léger espace
                canvas.line(x_left, cur_y, x_right, cur_y)
                canvas.restoreState()
                cur_y -= 2
            elif t == 'text':
                # Texte sur toute la largeur (utile pour bandeaux titre/sous-titre)
                txt = _hf_interpolate(b.get('text') or '', data, doc)
                if not txt: continue
                fs = int(b.get('font_size') or 9)
                color_hex = b.get('color') or '#0F172A'
                align = (b.get('align') or 'center').lower()
                bold = bool(b.get('bold', False))
                font = 'Helvetica-Bold' if bold else 'Helvetica'
                canvas.saveState()
                canvas.setFont(font, fs)
                canvas.setFillColor(colors.HexColor(color_hex))
                cur_y -= fs + 2
                if align == 'left':
                    canvas.drawString(x_left, cur_y, txt)
                elif align == 'right':
                    canvas.drawRightString(x_right, cur_y, txt)
                else:
                    canvas.drawCentredString(x_center, cur_y, txt)
                canvas.restoreState()
            elif t == 'image':
                img_path = ''
                if b.get('use_societe_logo'):
                    img_path = (data.get('societe_logo_path') or '').strip()
                else:
                    rel = (b.get('path') or '').strip()
                    if rel:
                        img_path = os.path.join(HERE, rel)
                        if not os.path.exists(img_path):
                            img_path = rel if os.path.exists(rel) else ''
                if not img_path or not os.path.exists(img_path): continue
                wcm = float(b.get('width_cm') or 4.5)
                hcm = float(b.get('height_cm') or 1.0)
                align = (b.get('align') or 'left').lower()
                if align == 'right':
                    img_x = x_right - wcm*cm
                elif align == 'center':
                    img_x = x_center - (wcm*cm)/2
                else:
                    img_x = x_left
                cur_y -= hcm*cm
                try:
                    canvas.drawImage(img_path, img_x, cur_y, width=wcm*cm, height=hcm*cm,
                                     preserveAspectRatio=True, mask='auto')
                except Exception:
                    pass
            elif t == 'row':
                # Ligne 3 colonnes : items avec col=left/center/right
                items = b.get('items') or []
                # Hauteur de la ligne : max des hauteurs des items
                row_h = 0
                for it in items:
                    if not isinstance(it, dict): continue
                    it_type = it.get('type')
                    if it_type == 'image':
                        row_h = max(row_h, float(it.get('height_cm') or 1.0)*cm)
                    elif it_type == 'text':
                        row_h = max(row_h, (int(it.get('font_size') or 9) + 4))
                    elif it_type == 'spacer':
                        row_h = max(row_h, float(it.get('height_cm') or 0.2)*cm)
                if row_h <= 0: row_h = 16
                cur_y -= row_h
                # Dessiner chaque item dans sa colonne
                for it in items:
                    if not isinstance(it, dict): continue
                    col = it.get('col') or 'left'
                    if col == 'left':
                        anchor_x = x_left
                    elif col == 'right':
                        anchor_x = x_right
                    else:
                        anchor_x = x_center
                    it_type = it.get('type')
                    if it_type == 'text':
                        txt = _hf_interpolate(it.get('text') or '', data, doc)
                        if not txt: continue
                        fs = int(it.get('font_size') or 9)
                        color_hex = it.get('color') or '#0F172A'
                        bold = bool(it.get('bold', False))
                        font = 'Helvetica-Bold' if bold else 'Helvetica'
                        canvas.saveState()
                        canvas.setFont(font, fs)
                        canvas.setFillColor(colors.HexColor(color_hex))
                        ty = cur_y + (row_h - fs)/2 + 1
                        if col == 'left':
                            canvas.drawString(anchor_x, ty, txt)
                        elif col == 'right':
                            canvas.drawRightString(anchor_x, ty, txt)
                        else:
                            canvas.drawCentredString(anchor_x, ty, txt)
                        canvas.restoreState()
                    elif it_type == 'image':
                        img_path = ''
                        if it.get('use_societe_logo'):
                            img_path = (data.get('societe_logo_path') or '').strip()
                        else:
                            rel = (it.get('path') or '').strip()
                            if rel:
                                img_path = os.path.join(HERE, rel)
                                if not os.path.exists(img_path):
                                    img_path = rel if os.path.exists(rel) else ''
                        if not img_path or not os.path.exists(img_path): continue
                        wcm = float(it.get('width_cm') or 4.5)
                        hcm = float(it.get('height_cm') or row_h/cm)
                        if col == 'left':
                            img_x = anchor_x
                        elif col == 'right':
                            img_x = anchor_x - wcm*cm
                        else:
                            img_x = anchor_x - (wcm*cm)/2
                        try:
                            canvas.drawImage(img_path, img_x, cur_y, width=wcm*cm, height=hcm*cm,
                                             preserveAspectRatio=True, mask='auto')
                        except Exception:
                            pass
        except Exception as _e:
            try:
                import logging as _lg
                _lg.error(f"[hf-blocks] Bloc ignoré ({b.get('type')}) : {_e}")
            except Exception:
                pass
            continue


def _draw_header_footer(canvas, doc):
    """En-tête et pied de page : utilise les blocs configurés depuis la cover_page de la société.
    Si pas de blocs configurés, fallback sur le header/footer historique (logo SOCOM + N° bon).
    v218.85"""
    canvas.saveState()
    W, H = A4
    data = getattr(doc, '_header_info', {}) or {}
    header_blocks = data.get('_header_blocks') or []
    footer_blocks = data.get('_footer_blocks') or []

    if header_blocks:
        # Zone header : du haut de la page (~2 cm)
        header_area = {
            'x': 1.5*cm,
            'y': H - 2.0*cm,  # bas de la zone header
            'w': W - 3.0*cm,
            'h': 1.6*cm,
        }
        _draw_hf_blocks(canvas, doc, header_blocks, data, header_area)
    else:
        # Fallback historique : logo SOCOM + n° de bon + date + trait bleu
        logo_path = _pick_logo()
        if logo_path:
            try:
                canvas.drawImage(
                    logo_path,
                    1.2*cm, H - 1.6*cm,
                    width=4.5*cm, height=1.0*cm,
                    preserveAspectRatio=True, mask='auto'
                )
            except Exception:
                pass
        numero = data.get('numero_iv', '') or ''
        date_iv = data.get('date', '') or ''
        if numero or date_iv:
            canvas.setFont('Helvetica-Bold', 11)
            canvas.setFillColor(ACCENT)
            parts = []
            if numero: parts.append(numero)
            if date_iv: parts.append(date_iv)
            canvas.drawRightString(W - 1.2*cm, H - 1.3*cm, "  —  ".join(parts))
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1.5)
        canvas.line(1.5*cm, H - 1.8*cm, W - 1.5*cm, H - 1.8*cm)

    if footer_blocks:
        # Zone footer : 1.4 cm de hauteur en bas
        footer_area = {
            'x': 1.5*cm,
            'y': 0.4*cm,  # tout en bas
            'w': W - 3.0*cm,
            'h': 1.4*cm,
        }
        _draw_hf_blocks(canvas, doc, footer_blocks, data, footer_area)
    else:
        # Fallback historique
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(W - 1.5*cm, 1*cm, f"Page {doc.page}")
        canvas.drawString(1.5*cm, 1*cm, "SOCOM S.A. — 10 rue du Commerce — L-3895 FOETZ")
    canvas.restoreState()


def _section_title(text, styles, width=None, icon=None):
    """Titre de section : texte blanc sur fond bleu foncé SOCOM.
    Rendu via un Table de largeur configurable (default 17cm = pleine largeur).
    Si `icon` (slug) est fourni, l'icône PNG correspondante est insérée à gauche du texte.
    Cherche l'icône dans HERE/icons/modules/<slug>.png.
    """
    if width is None:
        width = 17*cm
    para = Paragraph(
        f'<font color="#FFFFFF" size="10"><b>{text}</b></font>',
        ParagraphStyle(
            'SectionTitleP',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            leading=12,
            leftIndent=0,
        )
    )
    # Tentative de chargement de l'icône
    icon_flowable = None
    if icon:
        slug = str(icon).strip().replace('/', '').replace('\\', '')
        if slug:
            icon_path = os.path.join(HERE, "icons", "modules", f"{slug}.png")
            if os.path.exists(icon_path):
                from reportlab.platypus import Image as RLImage
                try:
                    icon_flowable = RLImage(icon_path, width=0.5*cm, height=0.5*cm, kind='proportional')
                except Exception:
                    icon_flowable = None

    if icon_flowable is not None:
        # Tableau 2 colonnes : icône (0.7cm) + texte
        tbl = Table([[icon_flowable, para]], colWidths=[0.7*cm, width - 0.7*cm])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), ACCENT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (0, 0), 8),  # padding gauche pour l'icône
            ('RIGHTPADDING', (0, 0), (0, 0), 0),
            ('LEFTPADDING', (1, 0), (1, 0), 4),  # padding entre icône et texte
            ('RIGHTPADDING', (1, 0), (1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
    else:
        # Sans icône : Table 1 colonne (comportement historique)
        # v218.12 : padding interne mais largeur EXACTE pour matcher les tableaux suivants.
        # Les paddings sont absorbés DANS la largeur de la colonne (pas ajoutés autour).
        tbl = Table([[para]], colWidths=[width])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), ACCENT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        tbl.hAlign = 'LEFT'
    return tbl


def _info_row(label, value, styles):
    """Ligne étiquette/valeur pour bloc 'Informations générales'."""
    return [
        Paragraph(f'<font color="#64748B" size="8"><b>{label}</b></font>', styles['Normal']),
        Paragraph(f'<font color="#0F172A" size="9">{value or "—"}</font>', styles['Normal']),
    ]


def generate_rapport(data):
    """Génère un rapport PDF (bytes). Voir docstring du module pour le schéma data."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=2*cm, bottomMargin=1.2*cm,
        title="Rapport d'intervention SOCOM",
        author="SOCOM GMAO",
    )
    styles = getSampleStyleSheet()
    h_normal = ParagraphStyle(
        'HNormal', parent=styles['Normal'],
        fontSize=9, textColor=TEXT, leading=12
    )
    # Transmettre les infos au handler d'en-tête (N° bon + date en haut à droite)
    # v218.85 : passe aussi tous les data utiles + header/footer blocks
    doc._header_info = dict(data)  # copie complète des données pour interpolation
    doc._header_info['_header_blocks'] = data.get('header_blocks') or []
    doc._header_info['_footer_blocks'] = data.get('footer_blocks') or []

    story = []

    # ═════════ TITRE ═════════
    type_label = (data.get('type_label') or '').upper()
    technique_nom = (data.get('technique') or '').strip()
    # Mode maintenance : nouvelle mise en page avec logo projet centré + page break
    is_maintenance_layout = (type_label == 'MAINTENANCE')
    # Espace entre les sections (doublé en maintenance pour aérer la page 2)
    _sect_gap = 12 if is_maintenance_layout else 6

    if is_maintenance_layout:
        # v218.81 : si une page de garde personnalisée est fournie, on l'utilise
        cover_blocks = data.get('cover_page_blocks')
        # v218.84 : flags pour éviter de dupliquer gamme/observations plus bas
        _cover_has_gamme = False
        _cover_has_obs = False
        if cover_blocks and isinstance(cover_blocks, list) and len(cover_blocks) > 0:
            # Mode personnalisé : remplace tout le bloc titre+infos+logo
            story.extend(_render_cover_blocks(cover_blocks, data, styles))
            # Marquer qu'on a déjà rendu les infos générales pour skip plus bas
            _cover_custom_done = True
            # Détecter si la cover contient gamme/observations
            for _b in cover_blocks:
                if not isinstance(_b, dict): continue
                if _b.get('type') == 'gamme_maintenance': _cover_has_gamme = True
                elif _b.get('type') == 'observations':   _cover_has_obs = True
        else:
            _cover_custom_done = False
            # Espace libre en haut de page (avant le titre)
            story.append(Spacer(1, 1.5*cm))
            # Titre adapté selon le sous-type (Entretien / Visite / fallback Maintenance)
            sous_type = (data.get('sous_type') or '').strip()
            if sous_type:
                # Construire un titre du type "RAPPORT D'ENTRETIEN" / "RAPPORT DE VISITE"
                st_upper = sous_type.upper()
                # Préposition : "D'" pour les voyelles/H, "DE " sinon
                first = st_upper[0] if st_upper else ''
                prep = "D'" if first in 'AEIOUHÉÈÊÀÂÎÏÔÛÜ' else 'DE '
                titre_main = f"RAPPORT {prep}{st_upper}"
            else:
                titre_main = "RAPPORT DE MAINTENANCE"
            story.append(Paragraph(
                f"<b>{titre_main}</b>",
                ParagraphStyle('Title', fontSize=24, textColor=ACCENT, alignment=1,
                               spaceAfter=8, leading=30)
            ))
            # Sous-titre : nom de la technique (même taille que le titre)
            sous_titre_txt = ""
            if technique_nom and technique_nom not in ('—', ''):
                sous_titre_txt = technique_nom.upper()
            if sous_titre_txt:
                story.append(Paragraph(
                    f"<b>{sous_titre_txt}</b>",
                    ParagraphStyle('Subtitle', fontSize=24, textColor=ACCENT, alignment=1,
                                   spaceAfter=4, leading=30)
                ))
            # Espace libre sous le nom de la technique
            story.append(Spacer(1, 1.2*cm))
    else:
        _cover_custom_done = False
        if type_label == 'DEPANNAGE':
            titre = "RAPPORT D'INTERVENTION - DÉPANNAGE"
        elif type_label == 'MAINTENANCE':
            titre = "RAPPORT D'INTERVENTION - MAINTENANCE"
        else:
            titre = "RAPPORT D'INTERVENTION"

        story.append(Paragraph(
            f'<b>{titre}</b>',
            ParagraphStyle('Title', fontSize=14, textColor=ACCENT, alignment=1, spaceAfter=6)
        ))

    # ═════════ LOGO SÉCURITÉ (PPSS + EPI) ═════════
    # Pas affiché en layout maintenance (la 1re page contient infos + logo projet + opérations)
    if not is_maintenance_layout and os.path.exists(LOGO_SECU):
        try:
            img_secu = Image(LOGO_SECU, width=3*cm, height=2*cm, kind='proportional')
            logos_table = Table([[img_secu]], colWidths=[17*cm])
            logos_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
            story.append(logos_table)
            story.append(Spacer(1, 4))
        except Exception:
            pass

    # ═════════ INFORMATIONS GÉNÉRALES ═════════
    client = data.get('client', '—') or '—'
    numero_projet = (data.get('numero_projet', '') or '').strip()
    projet_nom = (data.get('projet_nom', '') or '').strip()
    # Construction intelligente du libellé projet
    if numero_projet and numero_projet != '—' and projet_nom:
        projet_txt = f"{numero_projet} — {projet_nom}"
    elif numero_projet and numero_projet != '—':
        projet_txt = numero_projet
    elif projet_nom:
        projet_txt = projet_nom
    else:
        projet_txt = '—'

    # v218.81 : si une page de garde personnalisée a déjà rendu ces blocs, on saute
    if not _cover_custom_done:
        info_data = [
            _info_row('Client', client, styles),
            _info_row('Projet', projet_txt, styles),
        ]
        info_table = Table(info_data, colWidths=[5*cm, 12*cm])
        info_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
            ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
        ]))
        story.append(KeepTogether([_section_title("INFORMATIONS GÉNÉRALES", styles), info_table]))
        story.append(Spacer(1, _sect_gap))

    # ═════════ MODE MAINTENANCE : LOGO PROJET CENTRÉ + OPÉRATIONS + PAGE BREAK ═════════
    if is_maintenance_layout:
        # Logo projet centré (si fourni dans les data) — sauf si déjà rendu via cover
        projet_logo_path = (data.get('projet_logo_path') or '').strip()
        if not _cover_custom_done and projet_logo_path and os.path.exists(projet_logo_path):
            try:
                # Espace libre au-dessus du logo
                story.append(Spacer(1, 1*cm))
                # Dimensions max : 8 cm de large, 5 cm de haut, ratio préservé
                logo_proj = Image(projet_logo_path, width=8*cm, height=5*cm, kind='proportional')
                logo_proj_table = Table([[logo_proj]], colWidths=[17*cm])
                logo_proj_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('TOPPADDING', (0, 0), (-1, -1), 0),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                ]))
                story.append(logo_proj_table)
                # Espace libre en dessous du logo
                story.append(Spacer(1, 1*cm))
            except Exception as e:
                # Si l'image est corrompue ou format non géré, on continue sans crasher
                pass

        # Tableau OPÉRATIONS DE LA GAMME DE MAINTENANCE (déplacé ici depuis plus bas)
        # v218.84 : sauter si déjà rendu via la cover personnalisée
        gamme_ops_list_main = data.get('gamme_operations') or []
        has_gamme_ops_main = any(g.get('operations') for g in gamme_ops_list_main)
        if has_gamme_ops_main and not _cover_has_gamme:
            def _xml_esc_main(s):
                return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            check_rows_main = []
            for g in gamme_ops_list_main:
                ops = g.get('operations') or []
                if not ops:
                    continue
                if len(gamme_ops_list_main) > 1 and g.get('gamme_nom'):
                    check_rows_main.append([
                        Paragraph(f'<font color="#1E3A8A"><b>{_xml_esc_main(g["gamme_nom"])}</b></font>', h_normal),
                    ])
                for op in ops:
                    if isinstance(op, dict):
                        desc = op.get('description','') or ''
                        done = op.get('done', False)
                    else:
                        desc = str(op); done = False
                    if done:
                        box = '<font name="Helvetica-Bold" size="13" color="#10B981">&#10003;</font>'
                        check_rows_main.append([
                            Paragraph(f'{box}&nbsp;&nbsp;{_xml_esc_main(desc)}', h_normal)
                        ])
                    else:
                        # Pas de marque pour les opérations non réalisées (juste indentation pour aligner)
                        check_rows_main.append([
                            Paragraph(f'<font size="13">&nbsp;&nbsp;&nbsp;</font>&nbsp;&nbsp;{_xml_esc_main(desc)}', h_normal)
                        ])
            if check_rows_main:
                check_table_main = Table(check_rows_main, colWidths=[17*cm])
                check_table_main.setStyle(TableStyle([
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LINEBELOW', (0, 0), (-1, -2), 0.3, LIGHT),
                ]))
                # Le titre suit avec le tableau (KeepTogether sur les 2 premières lignes seulement)
                story.append(_section_title("OPÉRATIONS DE LA GAMME DE MAINTENANCE", styles))
                story.append(check_table_main)
                story.append(Spacer(1, _sect_gap))

        # ═════════ OBSERVATIONS (bon de maintenance uniquement) ═════════
        # v215.3 : récupérer les observations du PREMIER compte-rendu et les afficher
        # sous le tableau de la gamme. Les CR ne sont pas affichés sur les bons de maintenance,
        # mais leur observation est utile pour le rapport.
        # v218.84 : sauter si déjà rendu via la cover personnalisée
        cr_list = data.get('comptes_rendus') or []
        if cr_list and not _cover_has_obs:
            first_cr = cr_list[0]
            obs_text = (first_cr.get('observations') or '').strip()
            if obs_text:
                def _xml_esc_obs(s):
                    return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                obs_para = Paragraph(
                    _xml_esc_obs(obs_text).replace('\n', '<br/>'),
                    ParagraphStyle('obs_maint', fontSize=10, leading=13,
                                   textColor=colors.HexColor("#0f172a"))
                )
                obs_table = Table([[obs_para]], colWidths=[17*cm])
                obs_table.setStyle(TableStyle([
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
                    ('LEFTPADDING', (0, 0), (-1, -1), 12),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                    ('TOPPADDING', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(KeepTogether([
                    _section_title("OBSERVATIONS", styles),
                    obs_table,
                ]))
                story.append(Spacer(1, _sect_gap))

        # PAGE BREAK FORCÉ : page 1 = titre + infos + logo + opérations uniquement
        # Le reste (équipement + comptes-rendus + total) enchaîne sur la page 2
        story.append(PageBreak())

    # ═════════ ÉQUIPEMENT CONCERNÉ ═════════
    # Construction dynamique : on n'affiche une ligne que si la donnée est renseignée
    # v218.87 : si un module 'equipement' a été configuré dans la tuile, on saute le rendu legacy
    _has_equipement_module = False
    try:
        _modules_check = data.get('mesures_techniques') or []
        for _m in _modules_check:
            if (_m.get('type') or '').lower() == 'equipement':
                _has_equipement_module = True
                break
    except Exception:
        pass

    if not _has_equipement_module:
        # Collecte des paires (label, value) à afficher
        eq_pairs = [('Désignation', data.get('equipement', '—') or '—')]
        mm_ = (data.get('marque_modele') or '').strip()
        if mm_ and mm_ != '—':
            eq_pairs.append(('Marque / Modèle', mm_))
        if data.get('eq_puissance'):
            eq_pairs.append(('Puissance', data['eq_puissance']))
        if data.get('eq_numero_serie'):
            eq_pairs.append(('N° de série', data['eq_numero_serie']))
        if data.get('eq_in_out'):
            eq_pairs.append(('Int. / Ext.', data['eq_in_out']))
        if data.get('localisation') and data.get('localisation') not in ('—', ''):
            eq_pairs.append(('Localisation', data['localisation']))
        if data.get('tableau'):
            eq_pairs.append((data.get('tableau_label') or 'Tableau', data['tableau']))
        if data.get('technique') and data.get('technique') not in ('—', ''):
            eq_pairs.append(('Technique', data['technique']))
        if data.get('eq_date_mise_service'):
            eq_pairs.append(('Mise en service', data['eq_date_mise_service']))
        if data.get('eq_statut'):
            _statut_labels = {
                'EN_SERVICE': 'En service', 'HORS_SERVICE': 'Hors service',
                'EN_PANNE': 'En panne', 'EN_MAINTENANCE': 'En maintenance', 'ARCHIVE': 'Archivé',
            }
            st = data['eq_statut']
            eq_pairs.append(('Statut', _statut_labels.get(st, st)))

        # Layout 2 colonnes : 4 cellules par ligne (label | val | label | val)
        def _cell_label(txt):
            return Paragraph(f'<font color="#64748B" size="8"><b>{txt}</b></font>', styles['Normal'])
        def _cell_val(txt):
            return Paragraph(f'<font color="#0F172A" size="9">{txt or "—"}</font>', styles['Normal'])

        eq_rows = []
        for i in range(0, len(eq_pairs), 2):
            left = eq_pairs[i]
            right = eq_pairs[i+1] if i+1 < len(eq_pairs) else (None, None)
            row = [_cell_label(left[0]), _cell_val(left[1]),
                   _cell_label(right[0]) if right[0] else '',
                   _cell_val(right[1]) if right[0] else '']
            eq_rows.append(row)

        # Notes sur toute la largeur (si présentes) — via ligne fusionnée
        notes_row_idx = None
        if data.get('eq_notes'):
            notes = data['eq_notes'].replace('\n', '<br/>')
            notes_row_idx = len(eq_rows)
            eq_rows.append([
                _cell_label('Notes'),
                Paragraph(f'<font color="#0F172A" size="9">{notes}</font>', styles['Normal']),
                '', ''
            ])

        eq_table = Table(eq_rows, colWidths=[3*cm, 5.5*cm, 3*cm, 5.5*cm])
        style_cmds = [
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
            ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
        ]
        # Si la ligne Notes existe, on fusionne val sur 3 cellules pour étendre
        if notes_row_idx is not None:
            style_cmds.append(('SPAN', (1, notes_row_idx), (3, notes_row_idx)))
        eq_table.setStyle(TableStyle(style_cmds))
        story.append(KeepTogether([_section_title("ÉQUIPEMENT CONCERNÉ", styles), eq_table]))
        story.append(Spacer(1, _sect_gap))

    # v218.94 : Sections TRANSFORMATEUR et CELLULES retirées du rendu en dur.
    # Elles sont désormais disponibles uniquement via le module 'equipement' configuré dans la tuile
    # (champs trafo_* et toggle show_cellules).

    # ═════════ DESCRIPTIF (saisi à la création du bon) ═════════
    descriptif = (data.get('description') or '').strip()
    is_maint = data.get('is_maintenance')
    gamme_ops_list = data.get('gamme_operations') or []
    has_gamme_ops = is_maint and any(g.get('operations') for g in gamme_ops_list)

    if has_gamme_ops:
        # En mode maintenance layout, le tableau des opérations a déjà été rendu en page 1
        # avant le PageBreak. Ici on saute donc cette partie pour ne pas la dupliquer.
        if not is_maintenance_layout:
            # MAINTENANCE (ancien layout) : remplacer le descriptif par la liste des opérations en checklist
            def _xml_esc_d(s):
                return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            check_rows = []
            for g in gamme_ops_list:
                ops = g.get('operations') or []
                if not ops:
                    continue
                # Optionnel : titre de gamme si plusieurs gammes
                if len(gamme_ops_list) > 1 and g.get('gamme_nom'):
                    check_rows.append([
                        Paragraph(f'<font color="#1E3A8A"><b>{_xml_esc_d(g["gamme_nom"])}</b></font>', h_normal),
                    ])
                for op in ops:
                    # Compatibilité : op peut être une string (ancien format) ou un dict (avec statut)
                    if isinstance(op, dict):
                        desc = op.get('description','') or ''
                        done = op.get('done', False)
                        date_real = op.get('date_realisation','') or ''
                        tech_nom = op.get('technicien_nom','') or ''
                    else:
                        desc = str(op)
                        done = False
                        date_real = ''
                        tech_nom = ''
                    if done:
                        box = '<font name="Helvetica-Bold" size="13" color="#10B981">&#10003;</font>'
                        check_rows.append([
                            Paragraph(f'{box}&nbsp;&nbsp;{_xml_esc_d(desc)}', h_normal)
                        ])
                    else:
                        check_rows.append([
                            Paragraph(f'<font size="13">&nbsp;&nbsp;&nbsp;</font>&nbsp;&nbsp;{_xml_esc_d(desc)}', h_normal)
                        ])
            if check_rows:
                check_table = Table(check_rows, colWidths=[17*cm])
                check_table.setStyle(TableStyle([
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LINEBELOW', (0, 0), (-1, -2), 0.3, LIGHT),
                ]))
                story.append(KeepTogether([_section_title("OPÉRATIONS DE LA GAMME DE MAINTENANCE", styles), check_table]))
                story.append(Spacer(1, _sect_gap))

        # Tableau des sous-équipements (affiché dans les 2 modes : ancien et nouveau layout)
        gamme_sub = data.get('gamme_maintenance') or []
        if gamme_sub:
            def _xml_esc_s(s):
                return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            sub_rows = [['Sous-équipement', 'Localisation', 'Date de réalisation', 'CR']]
            for g in gamme_sub:
                nom = g.get('nom','') or '—'
                loc = g.get('localisation','') or ''
                dt = g.get('date_realisation','') or '—'
                num = g.get('cr_numero','') or ''
                sub_rows.append([
                    Paragraph(_xml_esc_s(nom), styles['Normal']),
                    Paragraph(_xml_esc_s(loc), styles['Normal']),
                    Paragraph(_xml_esc_s(dt), styles['Normal']),
                    Paragraph(_xml_esc_s(num), styles['Normal']),
                ])
            sub_table = Table(sub_rows, colWidths=[5.5*cm, 4*cm, 4*cm, 3.5*cm])
            sub_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT]),
            ]))
            story.append(sub_table)
            story.append(Spacer(1, _sect_gap))
    elif descriptif:
        # Comportement classique : afficher la description texte
        descriptif_html = descriptif.replace('\n', '<br/>')
        desc_para = Paragraph(descriptif_html, h_normal)
        desc_cell = Table([[desc_para]], colWidths=[17*cm])
        desc_cell.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        label = "DESCRIPTIF DU DÉPANNAGE" if type_label == 'DEPANNAGE' else "DESCRIPTIF DE L'INTERVENTION"
        story.append(KeepTogether([_section_title(label, styles), desc_cell]))
        story.append(Spacer(1, _sect_gap))

    # ═════════ COMPTES-RENDUS D'INTERVENTION ═════════
    # v213.7 : sur les bons de MAINTENANCE, on ne montre PAS les comptes-rendus ni le total général.
    # Les CR sont uniquement utiles pour les bons d'intervention (dépannage).
    crs = data.get('comptes_rendus') or []
    if crs and not is_maintenance_layout:
        section_title_block = _section_title("COMPTES-RENDUS D'INTERVENTION", styles)
        cr_elements = []
        total_general = 0.0  # Somme de toutes les heures, tous CRs confondus
        for i, cr in enumerate(crs):
            # En-tête du CR
            cr_num_str = cr.get('numero', '') or ''
            header_left = f'Compte-rendu n° {i+1}'
            if cr_num_str:
                header_left += f' — {cr_num_str}'
            cr_header = Table(
                [[
                    Paragraph(
                        f'<font color="#1E3A8A" size="10"><b>{header_left}</b></font>',
                        styles['Normal']
                    ),
                    Paragraph(
                        f'<font color="#64748B" size="9">Date d\'intervention : <b>{cr.get("date","—")}</b></font>',
                        ParagraphStyle('rh', parent=styles['Normal'], alignment=2)
                    )
                ]],
                colWidths=[8.5*cm, 8.5*cm]
            )
            cr_header.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
            ]))

            # Observations (support HTML minimal)
            obs_text = (cr.get('observations') or '').strip() or "—"
            # Si pas de HTML déjà présent, remplacer les \n
            if '<br' not in obs_text and '<p' not in obs_text:
                obs_text = obs_text.replace('\n', '<br/>')
            obs_para = Paragraph(obs_text, h_normal)
            obs_cell = Table([[obs_para]], colWidths=[17*cm])
            obs_cell.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                ('LINEABOVE', (0, 0), (-1, 0), 0, colors.white),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))

            # Tableau des intervenants avec heures
            intervenants_cr = cr.get('intervenants') or []
            if intervenants_cr:
                iv_rows = [["Technicien", "Date", "Début", "Fin", "Total"]]
                total_cr = 0.0
                for iv in intervenants_cr:
                    iv_rows.append([
                        iv.get('nom', '—') or '—',
                        iv.get('date', '—') or '—',
                        iv.get('heure_debut', '—') or '—',
                        iv.get('heure_fin', '—') or '—',
                        _format_heures(iv.get('total_heures', 0)),
                    ])
                    try:
                        total_cr += float(iv.get('total_heures', 0) or 0)
                    except Exception:
                        pass
                total_general += total_cr  # ← accumulation pour le total global
                iv_rows.append(["", "", "", "TOTAL CR", _format_heures(total_cr)])
                iv_table = Table(iv_rows, colWidths=[6*cm, 3*cm, 2.5*cm, 2.5*cm, 3*cm])
                iv_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), LIGHT),
                    ('TEXTCOLOR', (0, 0), (-1, 0), ACCENT),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('GRID', (0, 0), (-1, -2), 0.3, BORDER),
                    ('LINEBELOW', (0, 0), (-1, 0), 0.5, ACCENT),
                    ('FONTNAME', (3, -1), (-1, -1), 'Helvetica-Bold'),
                    ('TEXTCOLOR', (3, -1), (-1, -1), ACCENT),
                    ('LINEABOVE', (0, -1), (-1, -1), 1, ACCENT),
                ]))
                cr_block = KeepTogether([cr_header, obs_cell, Spacer(1, 4), iv_table, Spacer(1, 6)])
            else:
                cr_block = KeepTogether([cr_header, obs_cell, Spacer(1, 6)])

            # Le 1er CR est groupé avec le titre de section (évite titre orphelin en bas de page)
            # Sauf en mode maintenance : on laisse le titre seul pour que les sections enchainent fluidement
            if i == 0 and section_title_block is not None:
                if is_maintenance_layout:
                    # Ajouter le titre séparément (pas de KeepTogether)
                    cr_elements.append(section_title_block)
                else:
                    cr_block = KeepTogether([section_title_block, cr_block])
                section_title_block = None
            cr_elements.append(cr_block)

            # Photos du CR : grille 2 colonnes, hors KeepTogether (peuvent paginer)
            photos = cr.get('photos') or []
            if photos:
                photo_cells = []
                row_buf = []
                for ph_bytes in photos:
                    try:
                        img = Image(io.BytesIO(ph_bytes), width=8.2*cm, height=6.15*cm, kind='proportional')
                        row_buf.append(img)
                        if len(row_buf) == 2:
                            photo_cells.append(row_buf)
                            row_buf = []
                    except Exception:
                        continue
                if row_buf:
                    while len(row_buf) < 2:
                        row_buf.append('')
                    photo_cells.append(row_buf)
                if photo_cells:
                    photos_label = Paragraph(
                        f'<font color="#1E3A8A" size="9"><b>Photos ({len(photos)})</b></font>',
                        styles['Normal']
                    )
                    cr_elements.append(Spacer(1, 4))
                    cr_elements.append(photos_label)
                    cr_elements.append(Spacer(1, 3))
                    photos_table = Table(photo_cells, colWidths=[8.5*cm, 8.5*cm], hAlign='CENTER')
                    photos_table.setStyle(TableStyle([
                        ('LEFTPADDING', (0, 0), (-1, -1), 2),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 2),
                        ('TOPPADDING', (0, 0), (-1, -1), 2),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ]))
                    cr_elements.append(photos_table)
                    cr_elements.append(Spacer(1, 6))

        # Titre seul puis CRs un par un (chaque CR reste groupé via son propre KeepTogether)
        for block in cr_elements:
            story.append(block)

        # ═════════ TOTAL GÉNÉRAL DES HEURES ═════════
        # Affiché en bas de la section, cumule toutes les heures de tous les CRs
        total_rows = [[
            Paragraph(
                f'<font size="10" color="#1E3A8A"><b>TOTAL GÉNÉRAL DE L\'INTERVENTION</b></font>',
                styles['Normal']
            ),
            Paragraph(
                f'<font size="11" color="#1E3A8A"><b>{_format_heures(total_general)}</b></font>',
                ParagraphStyle('tg', parent=styles['Normal'], alignment=2)
            )
        ]]
        total_table = Table(total_rows, colWidths=[11*cm, 6*cm])
        total_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
            ('BOX', (0, 0), (-1, -1), 1.2, ACCENT),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(Spacer(1, 2))
        story.append(total_table)
        story.append(Spacer(1, _sect_gap))

    # ═════════ MODULES DE STRUCTURE RAPPORT (tableau / texte / checklist) ═════════
    # Affichés après les comptes-rendus / total. Configurables depuis les paramètres.
    mesures_techniques = data.get('mesures_techniques') or []
    def _xml_esc_m(s):
        return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    # v213 — Largeur des modules (pleine / demi)
    # On veut afficher 2 modules 'demi' consécutifs côte à côte dans un Table 2 colonnes.
    # Stratégie : on traite toujours la liste séquentiellement, mais on intercepte
    # `story.append` pour rediriger vers une sub-story quand on est en mode 'demi-pair'.
    _real_story_modules = story
    # Calculer pour chaque index si le bloc fait partie d'une paire 'demi-demi'
    # Format des entrées : ('solo', None) ou ('first_of_pair', None) ou ('second_of_pair', None)
    _pair_info = []
    _idx_pair = 0
    while _idx_pair < len(mesures_techniques):
        _b1m = mesures_techniques[_idx_pair]
        _l1m = (_b1m.get('largeur') or 'pleine').lower()
        _p1m = int(_b1m.get('page_num') or 1)
        if _l1m == 'demi' and _idx_pair + 1 < len(mesures_techniques):
            _b2m = mesures_techniques[_idx_pair + 1]
            _l2m = (_b2m.get('largeur') or 'pleine').lower()
            _p2m = int(_b2m.get('page_num') or 1)
            # Apparier uniquement si les 2 modules sont 'demi' ET sur la même page
            if _l2m == 'demi' and _p1m == _p2m:
                _pair_info.append('first_of_pair')
                _pair_info.append('second_of_pair')
                _idx_pair += 2
                continue
        _pair_info.append('solo')
        _idx_pair += 1

    _sub_left = None  # sub-story du premier élément de la paire en cours
    _sub_right = None  # sub-story du second
    _pending_pair_close = False  # flag : la paire vient juste d'être complétée, à fermer au prochain tour
    _current_page_num = 1  # v214 : suivi de la page courante pour insérer des PageBreak

    class _PairSubStory(list):
        """Liste qui décompose les KeepTogether en flowables simples au moment de l'append.
        Nécessaire pour que les éléments soient drawables dans une cellule de Table."""
        def append(self, item):
            if isinstance(item, KeepTogether):
                # Extraire les flowables internes (qui sont stockés dans _content ou directement)
                inner = getattr(item, '_content', None)
                if inner is None:
                    inner = getattr(item, '_flowables', None) or []
                for f in inner:
                    super().append(f)
            else:
                super().append(item)

    def _close_pair_into(real_story_target, sub_l, sub_r):
        """Construit un Table 2 colonnes avec les 2 sub-stories et l'ajoute à real_story_target."""
        # Largeur totale = 17cm (zone utile A4 avec marges 2cm) — alignée avec ÉQUIPEMENT CONCERNÉ.
        # Chaque module = 8.3cm + gap de 0.4cm au milieu = 17cm pile.
        _half_w = 8.3*cm
        _gap = 0.4*cm
        _content_l = list(sub_l) if sub_l else [Spacer(1, 1)]
        _content_r = list(sub_r) if sub_r else [Spacer(1, 1)]
        # 3 colonnes : module gauche / gap vide / module droite
        _pair_data = [[_content_l, '', _content_r]]
        _pair_table = Table(_pair_data, colWidths=[_half_w, _gap, _half_w], style=TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ]))
        # hAlign='CENTER' avec largeur 17cm = pile centré dans la zone utile
        _pair_table.hAlign = 'CENTER'
        real_story_target.append(_pair_table)
        real_story_target.append(Spacer(1, _sect_gap))

    for _bidx, bloc in enumerate(mesures_techniques):
        # Si la paire précédente vient d'être complétée → la fermer maintenant (avant de traiter le bloc courant)
        if _pending_pair_close:
            _close_pair_into(_real_story_modules, _sub_left, _sub_right)
            _sub_left = None
            _sub_right = None
            _pending_pair_close = False
            story = _real_story_modules

        # v214 : Si le module demande une page supérieure à la page courante,
        # insérer autant de PageBreak que nécessaire (saute en page demandée)
        _bloc_page = int(bloc.get('page_num') or 1)
        if _bloc_page > _current_page_num:
            for _ in range(_bloc_page - _current_page_num):
                _real_story_modules.append(PageBreak())
            _current_page_num = _bloc_page

        # Déterminer si on est solo / first / second of pair
        _pinfo = _pair_info[_bidx] if _bidx < len(_pair_info) else 'solo'
        if _pinfo == 'first_of_pair':
            _sub_left = _PairSubStory()
            story = _sub_left  # rediriger vers la colonne gauche
            _avail_w = 8.3*cm
        elif _pinfo == 'second_of_pair':
            _sub_right = _PairSubStory()
            story = _sub_right  # rediriger vers la colonne droite
            _pending_pair_close = True  # à fermer au prochain tour ou après la boucle
            _avail_w = 8.3*cm
        else:
            story = _real_story_modules
            _avail_w = 17*cm

        bloc_nom = bloc.get('nom', '') or ''
        bloc_type = (bloc.get('type') or 'tableau').lower()
        lignes = bloc.get('lignes') or []
        # Pour 'graphique', 'preconisations', 'mesures_batteries', 'image', 'equipement' et 'image_checklist', les lignes ne sont pas obligatoires
        if not lignes and bloc_type not in ('graphique', 'preconisations', 'mesures_batteries', 'image', 'equipement', 'image_checklist'):
            continue

        # ─── Type EQUIPEMENT : v218.87 — équivalent du tableau "Équipement concerné" historique, mais en module configurable ───
        if bloc_type == 'equipement':
            import json as _json
            # Lire la config (champs cochés + ratio)
            _eq_fopts_raw = bloc.get('field_options') or ''
            try:
                _eq_fopts = _json.loads(_eq_fopts_raw) if isinstance(_eq_fopts_raw, str) and _eq_fopts_raw else (_eq_fopts_raw if isinstance(_eq_fopts_raw, dict) else {})
            except Exception:
                _eq_fopts = {}
            # Champs activés (par défaut, tous les champs basiques + tous les champs trafo)
            _all_eq_fields = ['designation', 'marque_modele', 'puissance', 'numero_serie',
                              'in_out', 'localisation', 'tableau', 'technique',
                              'date_mise_service', 'statut', 'notes',
                              # v218.93 : champs trafo HT
                              'trafo_marque', 'trafo_annee', 'trafo_numero_serie', 'trafo_puissance_kva',
                              'trafo_refroidissement', 'trafo_poids_kg', 'trafo_tension_entree_v',
                              'trafo_courant_a', 'trafo_norme', 'trafo_couplage',
                              'trafo_tension_service_v', 'trafo_reglage_tension_kv']
            _eq_active = _eq_fopts.get('fields')
            if not isinstance(_eq_active, list) or not _eq_active:
                _eq_active = list(_all_eq_fields)
            # v218.93 : sections sous-tableaux (booléennes — défaut True)
            _show_cellules = bool(_eq_fopts.get('show_cellules', True))
            _show_tableaux = bool(_eq_fopts.get('show_tableaux', True))
            # v218.89 : ratio = fraction du label DANS UNE DEMI-LIGNE (label/(label+val) dans la moitié)
            _eq_label_ratio = 0.35
            try:
                _lr = _eq_fopts.get('label_ratio')
                if _lr is not None:
                    _lr_int = int(_lr)
                    if 15 <= _lr_int <= 60:
                        _eq_label_ratio = _lr_int / 100.0
            except Exception:
                pass

            # Construction des paires (label, value) selon les champs cochés
            _statut_labels_eq = {
                'EN_SERVICE': 'En service', 'HORS_SERVICE': 'Hors service',
                'EN_PANNE': 'En panne', 'EN_MAINTENANCE': 'En maintenance', 'ARCHIVE': 'Archivé',
            }
            _trafo = data.get('trafo') or {}
            _eq_field_specs = {
                # Champs basiques
                'designation':       ('Désignation',       data.get('equipement', '—') or '—'),
                'marque_modele':     ('Marque / Modèle',   (data.get('marque_modele') or '').strip()),
                'puissance':         ('Puissance',         data.get('eq_puissance') or ''),
                'numero_serie':      ('N° de série',       data.get('eq_numero_serie') or ''),
                'in_out':            ('Int. / Ext.',       data.get('eq_in_out') or ''),
                'localisation':      ('Localisation',      data.get('localisation') if data.get('localisation') not in ('—', '', None) else ''),
                'tableau':           (data.get('tableau_label') or 'Tableau', data.get('tableau') or ''),
                'technique':         ('Technique',         data.get('technique') if data.get('technique') not in ('—', '', None) else ''),
                'date_mise_service': ('Mise en service',   data.get('eq_date_mise_service') or ''),
                'statut':            ('Statut',            _statut_labels_eq.get(data.get('eq_statut',''), data.get('eq_statut',''))),
                # v218.93 : champs Trafo HT
                'trafo_marque':            ('Trafo · Marque',           _trafo.get('marque') or ''),
                'trafo_annee':             ('Trafo · Année',            _trafo.get('annee') or ''),
                'trafo_numero_serie':      ('Trafo · N° de série',      _trafo.get('numero_serie') or ''),
                'trafo_puissance_kva':     ('Trafo · Puissance (kVA)',  _trafo.get('puissance_kva') or ''),
                'trafo_refroidissement':   ('Trafo · Refroidissement',  _trafo.get('refroidissement') or ''),
                'trafo_poids_kg':          ('Trafo · Poids (kg)',       _trafo.get('poids_kg') or ''),
                'trafo_tension_entree_v':  ('Trafo · Tension entrée (V)', _trafo.get('tension_entree_v') or ''),
                'trafo_courant_a':         ('Trafo · Courant (A)',      _trafo.get('courant_a') or ''),
                'trafo_norme':             ('Trafo · Norme',            _trafo.get('norme') or ''),
                'trafo_couplage':          ('Trafo · Couplage',         _trafo.get('couplage') or ''),
                'trafo_tension_service_v': ('Trafo · Tension service (V)', _trafo.get('tension_service_v') or ''),
                'trafo_reglage_tension_kv':('Trafo · Réglage tension (kV)', _trafo.get('reglage_tension_kv') or ''),
            }
            _eq_pairs = []
            _notes_value = ''
            for _f in _eq_active:
                if _f not in _eq_field_specs and _f != 'notes':
                    continue
                if _f == 'notes':
                    _val = data.get('eq_notes') or ''
                    if _val and str(_val).strip():
                        _notes_value = _val
                    continue
                _lbl, _val = _eq_field_specs[_f]
                # Pour designation, on affiche toujours, pour les autres seulement si rempli
                if _f == 'designation' or (_val and str(_val).strip() not in ('', '—')):
                    _eq_pairs.append((_lbl, _val if _val else '—'))

            # Sous-équipements
            _cellules = data.get('cellules') or []
            _tableaux_eq = data.get('tableaux_eq') or []
            _has_cellules = _show_cellules and len(_cellules) > 0
            _has_tableaux = _show_tableaux and len(_tableaux_eq) > 0

            # Si rien à afficher au total, on saute
            if not _eq_pairs and not _notes_value and not _has_cellules and not _has_tableaux:
                continue

            def _eq_cell_label(txt):
                return Paragraph(f'<font color="#64748B" size="8"><b>{_xml_esc_m(txt)}</b></font>', styles['Normal'])
            def _eq_cell_val(txt):
                return Paragraph(f'<font color="#0F172A" size="9">{_xml_esc_m(str(txt))}</font>', styles['Normal'])

            # Layout 4 cellules (label | val | label | val) comme l'historique
            _eq_rows = []
            for _i in range(0, len(_eq_pairs), 2):
                _left = _eq_pairs[_i]
                _right = _eq_pairs[_i+1] if _i+1 < len(_eq_pairs) else (None, None)
                _row = [_eq_cell_label(_left[0]), _eq_cell_val(_left[1]),
                        _eq_cell_label(_right[0]) if _right[0] else '',
                        _eq_cell_val(_right[1]) if _right[0] else '']
                _eq_rows.append(_row)
            _eq_notes_row_idx = None
            if _notes_value:
                _notes_html = _xml_esc_m(_notes_value).replace('\n', '<br/>')
                _eq_notes_row_idx = len(_eq_rows)
                _eq_rows.append([
                    _eq_cell_label('Notes'),
                    Paragraph(f'<font color="#0F172A" size="9">{_notes_html}</font>', styles['Normal']),
                    '', ''
                ])

            # Calcul des largeurs (4 cellules)
            _half_w = _avail_w / 2.0
            _eq_lbl_w = _half_w * _eq_label_ratio
            _eq_val_w = _half_w - _eq_lbl_w
            _eq_lbl_w2 = _eq_lbl_w
            _eq_val_w2 = _avail_w - _eq_lbl_w - _eq_val_w - _eq_lbl_w2
            _eq_main_table = None
            if _eq_rows:
                _eq_main_table = Table(_eq_rows, colWidths=[_eq_lbl_w, _eq_val_w, _eq_lbl_w2, _eq_val_w2])
                _eq_style_cmds = [
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
                ]
                if _eq_notes_row_idx is not None:
                    _eq_style_cmds.append(('SPAN', (1, _eq_notes_row_idx), (3, _eq_notes_row_idx)))
                _eq_main_table.setStyle(TableStyle(_eq_style_cmds))

            # v218.93 : Sous-tableau Cellules HT
            _cellules_table = None
            if _has_cellules:
                # v218.95 : utiliser un ParagraphStyle dédié au header avec texte blanc explicite
                _hdr_style_white = ParagraphStyle(
                    '_eq_sub_hdr', parent=styles['Normal'],
                    fontName='Helvetica-Bold', fontSize=8,
                    textColor=colors.white, alignment=0
                )
                _cell_header = [
                    Paragraph('DÉSIGNATION', _hdr_style_white),
                    Paragraph('MARQUE', _hdr_style_white),
                    Paragraph('TYPE', _hdr_style_white),
                ]
                _cell_data = [_cell_header]
                for _c in _cellules:
                    _cell_data.append([
                        Paragraph(f'<font color="#0F172A" size="9">{_xml_esc_m(_c.get("designation",""))}</font>', styles['Normal']),
                        Paragraph(f'<font color="#0F172A" size="9">{_xml_esc_m(_c.get("marque",""))}</font>', styles['Normal']),
                        Paragraph(f'<font color="#0F172A" size="9">{_xml_esc_m(_c.get("type",""))}</font>', styles['Normal']),
                    ])
                _cellules_table = Table(_cell_data, colWidths=[_avail_w * 0.45, _avail_w * 0.30, _avail_w * 0.25])
                _cellules_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('LINEBELOW', (0, 0), (-1, -1), 0.3, BORDER),
                    ('GRID', (0, 1), (-1, -1), 0.3, BORDER),
                ]))

            # v218.93 : Sous-tableau Tableaux/Bornes
            _tab_eq_table = None
            if _has_tableaux:
                # v218.95 : style header texte blanc
                _hdr_style_white2 = ParagraphStyle(
                    '_eq_sub_hdr2', parent=styles['Normal'],
                    fontName='Helvetica-Bold', fontSize=8,
                    textColor=colors.white, alignment=0
                )
                _sub_label_plural = "BORNES" if (data.get('tableau_label') or 'Tableau').lower() == 'borne' else "TABLEAUX"
                _tab_header = [
                    Paragraph('NOM', _hdr_style_white2),
                    Paragraph('LOCALISATION', _hdr_style_white2),
                ]
                _tab_data = [_tab_header]
                for _t in _tableaux_eq:
                    _tab_data.append([
                        Paragraph(f'<font color="#0F172A" size="9">{_xml_esc_m(_t.get("nom",""))}</font>', styles['Normal']),
                        Paragraph(f'<font color="#0F172A" size="9">{_xml_esc_m(_t.get("localisation",""))}</font>', styles['Normal']),
                    ])
                _tab_eq_table = Table(_tab_data, colWidths=[_avail_w * 0.5, _avail_w * 0.5])
                _tab_eq_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('LINEBELOW', (0, 0), (-1, -1), 0.3, BORDER),
                    ('GRID', (0, 1), (-1, -1), 0.3, BORDER),
                ]))

            # Assembler tout
            _eq_title = bloc_nom.upper() if bloc_nom else 'ÉQUIPEMENT CONCERNÉ'
            _eq_title_obj = _section_title(_eq_title, styles, _avail_w, icon=bloc.get("icon"))
            try:
                _eq_title_obj.hAlign = 'CENTER'
            except Exception:
                pass
            _eq_assembly = [_eq_title_obj]
            if _eq_main_table is not None:
                _eq_assembly.append(_eq_main_table)
            # Sous-titres et tableaux pour cellules/tableaux
            def _sub_title(txt):
                # Petit titre intermédiaire avec fond gris clair
                _tbl = Table([[Paragraph(f'<font color="#1E3A8A" size="9"><b>{_xml_esc_m(txt)}</b></font>', styles['Normal'])]],
                             colWidths=[_avail_w])
                _tbl.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                return _tbl
            if _cellules_table is not None:
                _eq_assembly.append(Spacer(1, 4))
                _eq_assembly.append(_sub_title("Cellules HT"))
                _eq_assembly.append(_cellules_table)
            if _tab_eq_table is not None:
                _sub_label_plural = "Bornes" if (data.get('tableau_label') or 'Tableau').lower() == 'borne' else "Tableaux"
                _eq_assembly.append(Spacer(1, 4))
                _eq_assembly.append(_sub_title(_sub_label_plural))
                _eq_assembly.append(_tab_eq_table)
            story.append(KeepTogether(_eq_assembly))
            story.append(Spacer(1, _sect_gap))

        # ─── Type TABLEAU : 2 colonnes (Élément | Valeur) avec rendu adapté par type de champ ───
        if bloc_type == 'tableau':
            import json as _json
            # v218.86 : ratio de largeur libellé/valeur configurable par bloc (defaut 80%)
            _label_ratio = 0.8
            try:
                _bloc_fopts_raw = bloc.get('field_options') or ''
                _bloc_fopts = _json.loads(_bloc_fopts_raw) if isinstance(_bloc_fopts_raw, str) and _bloc_fopts_raw else (_bloc_fopts_raw if isinstance(_bloc_fopts_raw, dict) else {})
                _lr = _bloc_fopts.get('label_ratio')
                if _lr is not None:
                    _lr_int = int(_lr)
                    if 10 <= _lr_int <= 90:
                        _label_ratio = _lr_int / 100.0
            except Exception:
                pass
            # Helpers de style cohérents avec "Équipement concerné" / "Informations générales"
            # Le label est passé comme STRING BRUT pour empêcher tout retour à la ligne.
            # Le styling (couleur grise, gras, taille 8pt) est appliqué via TableStyle sur la colonne 0.
            def _mod_label(txt):
                return _xml_esc_m(txt)
            def _mod_val_html(html):
                return Paragraph(f'<font color="#0F172A" size="9">{html or "—"}</font>', styles['Normal'])

            mes_data = []
            # Style commands pour la coloration des cellules (binary) — pas de header donc row_idx commence à 0
            row_styles = []
            for idx, lg in enumerate(lignes):
                row_idx = idx
                ftype = (lg.get('field_type') or 'numeric').lower()
                val_raw = (lg.get('valeur') or '').strip()
                fopts_raw = lg.get('field_options') or ''
                fopts = {}
                if fopts_raw:
                    try:
                        fopts = _json.loads(fopts_raw) if isinstance(fopts_raw, str) else fopts_raw
                    except Exception:
                        fopts = {}

                if ftype == 'numeric':
                    unite = lg.get('unite','') or ''
                    if val_raw:
                        display = f"{_xml_esc_m(val_raw)} <font color='#94a3b8'>{_xml_esc_m(unite)}</font>" if unite else _xml_esc_m(val_raw)
                    else:
                        display = '—'
                    mes_data.append([_mod_label(lg.get("libelle","")), _mod_val_html(display)])

                elif ftype == 'binary':
                    label_off = (fopts.get('label_off') or 'Non').strip()
                    label_on  = (fopts.get('label_on')  or 'Oui').strip()
                    color_off = fopts.get('color_off') or '#DC2626'
                    color_on  = fopts.get('color_on')  or '#10B981'
                    if val_raw == '1':
                        display = f'<font color="{color_on}"><b>{_xml_esc_m(label_on)}</b></font>'
                        row_styles.append(('BACKGROUND', (1, row_idx), (1, row_idx), colors.HexColor('#ECFDF5')))
                    elif val_raw == '0':
                        display = f'<font color="{color_off}"><b>{_xml_esc_m(label_off)}</b></font>'
                        row_styles.append(('BACKGROUND', (1, row_idx), (1, row_idx), colors.HexColor('#FEE2E2')))
                    else:
                        display = '—'
                    mes_data.append([_mod_label(lg.get("libelle","")), _mod_val_html(display)])

                elif ftype == 'select':
                    display = f'<b>{_xml_esc_m(val_raw)}</b>' if val_raw else '—'
                    mes_data.append([_mod_label(lg.get("libelle","")), _mod_val_html(display)])

                elif ftype == 'text_long':
                    display = _xml_esc_m(val_raw).replace('\n', '<br/>') if val_raw else '—'
                    mes_data.append([_mod_label(lg.get("libelle","")), _mod_val_html(display)])

                elif ftype == 'text_pair':
                    # v216.1 : pas de libellé séparé pour text_pair
                    # Le premier texte sert de libellé (colonne gauche), le second de valeur (colonne droite)
                    parts = (val_raw or '').split('|||', 1)
                    p1 = parts[0].strip() if len(parts) >= 1 else ''
                    p2 = parts[1].strip() if len(parts) >= 2 else ''
                    # Colonne label = p1 (string brut, comme les autres labels) ou tiret si vide
                    left_label = p1 if p1 else '—'
                    right_val = _xml_esc_m(p2) if p2 else '—'
                    mes_data.append([left_label, _mod_val_html(right_val)])

                else:  # text_short
                    display = _xml_esc_m(val_raw) if val_raw else '—'
                    mes_data.append([_mod_label(lg.get("libelle","")), _mod_val_html(display)])

            mes_table = Table(mes_data, colWidths=[_avail_w * _label_ratio, _avail_w * (1.0 - _label_ratio)])
            base_style = [
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
                # Styles de la colonne 0 (label string brut) : gris foncé, gras, 8pt
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (0, -1), 8),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748B')),
            ]
            mes_table.setStyle(TableStyle(base_style + row_styles))
            story.append(KeepTogether([
                _section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")),
                mes_table,
            ]))
            story.append(Spacer(1, _sect_gap))

        # ─── Type TEXTE : zone de texte libre (paragraphe encadré) ───
        elif bloc_type == 'texte':
            txt = (lignes[0].get('valeur') or '').strip() if lignes else ''
            display_txt = txt if txt else '—'
            # Encadré gris clair pour le texte
            txt_para = Paragraph(_xml_esc_m(display_txt).replace('\n', '<br/>'),
                                 ParagraphStyle('texte_libre', fontSize=10, leading=13,
                                                textColor=colors.HexColor("#0f172a")))
            txt_table = Table([[txt_para]], colWidths=[_avail_w])
            txt_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ]))
            story.append(KeepTogether([
                _section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")),
                txt_table,
            ]))
            story.append(Spacer(1, _sect_gap))

        # ─── Type CHECKLIST : liste de cases à cocher ───
        elif bloc_type == 'checklist':
            check_rows_m = []
            for lg in lignes:
                val = (lg.get('valeur') or '').strip().lower()
                done = val in ('1', 'true', 'oui', 'yes', 'on', 'x')
                libelle_esc = _xml_esc_m(lg.get("libelle",""))
                if done:
                    box = '<font name="Helvetica-Bold" size="11" color="#10B981">&#10003;</font>'
                    check_rows_m.append([
                        Paragraph(f'{box}&nbsp;&nbsp;<font color="#0F172A" size="9">{libelle_esc}</font>', styles['Normal'])
                    ])
                else:
                    box = '<font name="Helvetica-Bold" size="11" color="#cbd5e1">&#9744;</font>'
                    check_rows_m.append([
                        Paragraph(f'{box}&nbsp;&nbsp;<font color="#0F172A" size="9">{libelle_esc}</font>', styles['Normal'])
                    ])
            check_table_m = Table(check_rows_m, colWidths=[_avail_w])
            check_table_m.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
            ]))
            story.append(KeepTogether([
                _section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")),
                check_table_m,
            ]))
            story.append(Spacer(1, _sect_gap))

        # ─── Type GRAPHIQUE : image PNG générée par matplotlib (pré-calculée côté serveur) ───
        elif bloc_type == 'graphique':
            png_bytes = bloc.get('graph_png')
            if png_bytes:
                from reportlab.platypus import Image as RLImage
                import io as _io_pdf
                img = RLImage(_io_pdf.BytesIO(png_bytes), width=_avail_w, height=8.5*cm * (_avail_w / (17*cm)), kind='proportional')
                story.append(_section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")))
                story.append(img)
            story.append(Spacer(1, _sect_gap))

        # ─── Type PRÉCONISATIONS : tableau des pièces de l'équipement avec préconisation calculée ───
        elif bloc_type == 'preconisations':
            pieces = bloc.get('pieces') or []
            if not pieces:
                # Tableau vide avec un message
                empty_para = Paragraph(
                    '<i>Aucune pièce enregistrée pour cet équipement.</i>',
                    ParagraphStyle('empty', fontSize=9, textColor=colors.HexColor('#64748b'), alignment=1)
                )
                empty_box = Table([[empty_para]], colWidths=[_avail_w])
                empty_box.setStyle(TableStyle([
                    ('BOX', (0,0), (-1,-1), 0.5, BORDER),
                    ('BACKGROUND', (0,0), (-1,-1), LIGHT),
                    ('LEFTPADDING', (0,0), (-1,-1), 12),
                    ('RIGHTPADDING', (0,0), (-1,-1), 12),
                    ('TOPPADDING', (0,0), (-1,-1), 12),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 12),
                ]))
                story.append(KeepTogether([
                    _section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")),
                    empty_box,
                ]))
            else:
                # Format date helper : v216.3 — n'affiche que l'année (YYYY)
                def _fmt_date_p(s):
                    if not s: return '—'
                    try:
                        return datetime.strptime(s, "%Y-%m-%d").strftime("%Y")
                    except Exception:
                        # Fallback : si la chaîne contient déjà 4 chiffres au début, prendre ces 4 chiffres
                        try:
                            ss = str(s).strip()
                            if len(ss) >= 4 and ss[:4].isdigit():
                                return ss[:4]
                        except Exception:
                            pass
                        return str(s)
                # Header
                hdr_style = ParagraphStyle('precoHdr', fontSize=8, textColor=colors.HexColor('#64748B'), fontName='Helvetica-Bold', leading=10)
                cell_style = ParagraphStyle('precoCell', fontSize=8, textColor=colors.HexColor('#0f172a'), leading=10)
                # v216.2 : 5 colonnes — Type / Référence / Nombre / Installation / Préconisation
                preco_data = [[
                    Paragraph('Type', hdr_style),
                    Paragraph('Référence', hdr_style),
                    Paragraph('Nombre', hdr_style),
                    Paragraph('Installation', hdr_style),
                    Paragraph('Préconisation', hdr_style),
                ]]
                row_styles_p = []
                LEVEL_COLORS = {
                    'critique': ('#DC2626', '#FEE2E2'),
                    'warning':  ('#F59E0B', '#FEF3C7'),
                    'info':     ('#3B82F6', '#DBEAFE'),
                    'ok':       ('#10B981', '#ECFDF5'),
                }
                def _xml_esc_p(s):
                    return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                for idx, pc in enumerate(pieces):
                    row_idx = idx + 1
                    level = (pc.get('preconisation_level') or 'ok')
                    prec_col_text, prec_col_bg = LEVEL_COLORS.get(level, ('#64748b','#F1F5F9'))
                    preco_html  = f'<font color="{prec_col_text}">{_xml_esc_p(pc.get("preconisation",""))}</font>'
                    # Quantité (default 1 si non renseignée)
                    qty_raw = pc.get('quantite')
                    try:
                        qty = int(qty_raw) if qty_raw not in (None, '') else 1
                    except (ValueError, TypeError):
                        qty = 1
                    # v216.7 : cellules courtes en strings bruts (pas de wrap automatique).
                    # Seule la colonne Préconisation reste en Paragraph car elle a du HTML coloré.
                    preco_data.append([
                        pc.get('type_piece','') or '',
                        pc.get('reference','') or '—',
                        str(qty),
                        _fmt_date_p(pc.get('date_installation')),
                        Paragraph(preco_html, cell_style),
                    ])
                    # Coloration de la cellule préconisation (col 4)
                    row_styles_p.append(('BACKGROUND', (4, row_idx), (4, row_idx), colors.HexColor(prec_col_bg)))
                # 5 colonnes : Type / Référence / Nombre / Installation / Préconisation
                # Plus de place pour Type et Préconisation
                preco_table = Table(preco_data, colWidths=[
                    _avail_w * 0.22,  # Type (élargie pour éviter wrap)
                    _avail_w * 0.18,  # Référence
                    _avail_w * 0.10,  # Nombre (assez large pour le header "Nombre")
                    _avail_w * 0.12,  # Installation (juste YYYY = court)
                    _avail_w * 0.38,  # Préconisation (élargie)
                ])
                base_style_p = [
                    # Header en gris clair (sous-titre, pas un bandeau bleu)
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#64748B')),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('LINEBELOW', (0, 0), (-1, 0), 0.5, BORDER),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('LINEBELOW', (0, 1), (-1, -2), 0.3, BORDER),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    # v216.7 : style des cellules en string brut (Type, Référence, Nombre, Installation)
                    ('FONTNAME', (0, 1), (3, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (3, -1), 8),
                    ('TEXTCOLOR', (0, 1), (3, -1), colors.HexColor('#0F172A')),
                    # Colonne Nombre + Installation centrées
                    ('ALIGN', (2, 1), (3, -1), 'CENTER'),
                ]
                preco_table.setStyle(TableStyle(base_style_p + row_styles_p))
                story.append(_section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")))
                story.append(preco_table)
            story.append(Spacer(1, _sect_gap))

        # ─── Type MESURES BATTERIES : grille 6 colonnes par chaîne, valeurs colorées ───
        elif bloc_type == 'mesures_batteries':
            chains = bloc.get('chains') or []
            bat_values = bloc.get('bat_values') or {}
            # Config tension nominale + tolérance
            bcfg = {}
            try:
                raw = bloc.get('field_options') or ''
                bcfg = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
            except Exception:
                bcfg = {}
            v_nom = float(bcfg.get('tension_nominale') or 12.0)
            tol_pct = float(bcfg.get('tolerance_pct') or 10.0)
            seuil_bas = v_nom * (1.0 - tol_pct / 100.0)
            seuil_haut = v_nom * (1.0 + tol_pct / 100.0)
            zone_safe_low = seuil_bas + (seuil_haut - seuil_bas) * 0.25
            zone_safe_high = seuil_haut - (seuil_haut - seuil_bas) * 0.25

            def _color_for(val):
                """Retourne (text_color, bg_color) selon la valeur."""
                if val is None:
                    return (colors.HexColor("#64748B"), colors.white)
                if val < seuil_bas or val > seuil_haut:
                    return (colors.HexColor("#DC2626"), colors.HexColor("#FEE2E2"))  # rouge
                if zone_safe_low <= val <= zone_safe_high:
                    return (colors.HexColor("#10B981"), colors.HexColor("#ECFDF5"))  # vert
                return (colors.HexColor("#F59E0B"), colors.HexColor("#FEF3C7"))  # orange

            story.append(_section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")))

            if not chains:
                empty_para_b = Paragraph(
                    f'<i>Aucune batterie d\u00e9tect\u00e9e sur cet \u00e9quipement (V_nom={v_nom}V, tol={tol_pct}%).</i>',
                    ParagraphStyle('empty_b', fontSize=9, textColor=colors.HexColor('#64748b'), alignment=1)
                )
                empty_box_b = Table([[empty_para_b]], colWidths=[_avail_w])
                empty_box_b.setStyle(TableStyle([
                    ('BOX', (0,0), (-1,-1), 0.5, BORDER),
                    ('BACKGROUND', (0,0), (-1,-1), LIGHT),
                    ('LEFTPADDING', (0,0), (-1,-1), 12),
                    ('RIGHTPADDING', (0,0), (-1,-1), 12),
                    ('TOPPADDING', (0,0), (-1,-1), 12),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 12),
                ]))
                story.append(empty_box_b)
            else:
                # Récap config en haut
                config_html = (
                    f'<font size="8" color="#64748b">Tension nominale : <b>{v_nom:g} V</b> &nbsp;|&nbsp; '
                    f'Tol\u00e9rance : <b>\u00b1{tol_pct:g}%</b> &nbsp;|&nbsp; '
                    f'Plage : <b>{seuil_bas:.2f} \u2013 {seuil_haut:.2f} V</b></font>'
                )
                # Wrapper dans un Table _avail_w pour alignement parfait avec _section_title
                _config_tbl = Table([[Paragraph(config_html, styles['Normal'])]], colWidths=[_avail_w])
                _config_tbl.setStyle(TableStyle([
                    ('LEFTPADDING', (0,0), (-1,-1), 0),
                    ('RIGHTPADDING', (0,0), (-1,-1), 0),
                    ('TOPPADDING', (0,0), (-1,-1), 2),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 2),
                ]))
                story.append(_config_tbl)
                story.append(Spacer(1, 4))

                # Pour chaque chaîne : un tableau 6 colonnes
                NCOLS = 6
                for chain in chains:
                    chain_idx = chain['chain_idx']
                    nb_bat = chain['nb_batteries']
                    chain_label = f"Cha\u00eene {chain_idx + 1} \u2014 {nb_bat} batterie(s) \u2014 type : {chain.get('piece_type','')}"
                    chain_para = Paragraph(
                        f'<font size="9" color="#1E3A8A"><b>{chain_label}</b></font>',
                        styles['Normal']
                    )
                    # Wrapper dans Table _avail_w pour alignement
                    _chain_tbl = Table([[chain_para]], colWidths=[_avail_w])
                    _chain_tbl.setStyle(TableStyle([
                        ('LEFTPADDING', (0,0), (-1,-1), 0),
                        ('RIGHTPADDING', (0,0), (-1,-1), 0),
                        ('TOPPADDING', (0,0), (-1,-1), 2),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
                    ]))
                    story.append(_chain_tbl)
                    story.append(Spacer(1, 3))

                    # Construire les lignes : nb_bat batteries réparties en NCOLS colonnes
                    # Chaque cellule : "Bn  /  12.5 V" (label + valeur colorée)
                    cell_data = []
                    cell_styles_b = []
                    nb_rows = (nb_bat + NCOLS - 1) // NCOLS
                    for r in range(nb_rows):
                        row_data = []
                        for c in range(NCOLS):
                            pos = r * NCOLS + c
                            if pos >= nb_bat:
                                row_data.append('')
                                continue
                            key = f'chain{chain_idx}_pos{pos}'
                            val_raw = bat_values.get(key, '')
                            try:
                                val = float(val_raw) if val_raw not in ('', None) else None
                            except Exception:
                                val = None
                            label = f'B{pos + 1}'
                            if val is not None:
                                cell_html = f'<b>{label}</b><br/><font size="10"><b>{val:g} V</b></font>'
                            else:
                                cell_html = f'<b>{label}</b><br/><font size="9" color="#94a3b8">\u2014</font>'
                            cell_para = Paragraph(cell_html,
                                ParagraphStyle('bat_cell', fontSize=8, leading=11, alignment=1)
                            )
                            row_data.append(cell_para)
                            # Coloration selon valeur
                            tcol, bgcol = _color_for(val)
                            row_idx_table = r
                            cell_styles_b.append(('BACKGROUND', (c, row_idx_table), (c, row_idx_table), bgcol))
                            cell_styles_b.append(('TEXTCOLOR', (c, row_idx_table), (c, row_idx_table), tcol))
                        cell_data.append(row_data)
                    if cell_data:
                        col_w = _avail_w / NCOLS
                        bat_tbl = Table(cell_data, colWidths=[col_w]*NCOLS)
                        base_b = [
                            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                            ('GRID', (0,0), (-1,-1), 0.4, BORDER),
                            ('LEFTPADDING', (0,0), (-1,-1), 3),
                            ('RIGHTPADDING', (0,0), (-1,-1), 3),
                            ('TOPPADDING', (0,0), (-1,-1), 4),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                        ]
                        bat_tbl.setStyle(TableStyle(base_b + cell_styles_b))
                        story.append(bat_tbl)
                    story.append(Spacer(1, 6))
            story.append(Spacer(1, _sect_gap))

        # ─── Type IMAGE : photo de l'équipement (v217) ───
        # ─── Type IMAGE_CHECKLIST : image à gauche + checklist à droite ───
        elif bloc_type == 'image_checklist':
            import json as _json_ic
            # Lire la config (image_path + ratio)
            _ic_fopts_raw = bloc.get('field_options') or ''
            try:
                _ic_fopts = _json_ic.loads(_ic_fopts_raw) if isinstance(_ic_fopts_raw, str) and _ic_fopts_raw else (_ic_fopts_raw if isinstance(_ic_fopts_raw, dict) else {})
            except Exception:
                _ic_fopts = {}
            _ic_image_rel = (_ic_fopts.get('image_path') or '').strip()
            _ic_ratio = 0.5
            try:
                _r = _ic_fopts.get('label_ratio')
                if _r is not None:
                    _ri = int(_r)
                    if 30 <= _ri <= 70:
                        _ic_ratio = _ri / 100.0
            except Exception:
                pass

            # Cellule gauche : l'image
            _ic_left_w = _avail_w * _ic_ratio
            _ic_right_w = _avail_w - _ic_left_w
            # v218.96 : taille fixe configurable (défaut 5cm), image centrée avec aspect ratio préservé
            _ic_size_cm = 5.0
            try:
                _isz = _ic_fopts.get('image_size_cm')
                if _isz is not None:
                    _isz_f = float(_isz)
                    if 2.0 <= _isz_f <= 12.0:
                        _ic_size_cm = _isz_f
            except Exception:
                pass
            _ic_box_size = _ic_size_cm * cm
            _ic_image_cell = None
            if _ic_image_rel:
                _ic_img_abs = os.path.join(HERE, _ic_image_rel)
                if not os.path.exists(_ic_img_abs):
                    _ic_img_abs = _ic_image_rel if os.path.exists(_ic_image_rel) else None
                if _ic_img_abs and os.path.exists(_ic_img_abs):
                    try:
                        from reportlab.platypus import Image as RLImage_ic
                        from PIL import Image as PILImageLib_ic
                        with PILImageLib_ic.open(_ic_img_abs) as _pim:
                            _iw, _ih = _pim.size
                        # Calcul de l'image redimensionnée pour rentrer dans le carré _ic_box_size
                        # en préservant le ratio (l'image fera au max _ic_box_size dans sa plus grande dimension)
                        if _iw > 0 and _ih > 0:
                            if _iw >= _ih:
                                _img_w = _ic_box_size
                                _img_h = _ic_box_size * (_ih / _iw)
                            else:
                                _img_h = _ic_box_size
                                _img_w = _ic_box_size * (_iw / _ih)
                        else:
                            _img_w = _ic_box_size
                            _img_h = _ic_box_size
                        _img_obj = RLImage_ic(_ic_img_abs, width=_img_w, height=_img_h)
                        # Wrapper dans une cellule de taille fixe pour garantir l'alignement uniforme
                        _ic_image_cell = Table(
                            [[_img_obj]],
                            colWidths=[_ic_box_size],
                            rowHeights=[_ic_box_size]
                        )
                        _ic_image_cell.setStyle(TableStyle([
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('LEFTPADDING', (0, 0), (-1, -1), 0),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                            ('TOPPADDING', (0, 0), (-1, -1), 0),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                        ]))
                    except Exception as _ic_e:
                        _ic_image_cell = Paragraph(
                            f'<i><font color="#94a3b8" size="9">Image illisible ({_xml_esc_m(str(_ic_e))})</font></i>',
                            styles["Normal"]
                        )
            if _ic_image_cell is None:
                # Pas d'image : on met quand même une cellule vide de la taille fixe pour aligner les modules
                _ic_image_cell = Table(
                    [[Paragraph('<i><font color="#94a3b8" size="9">Aucune image</font></i>', styles["Normal"])]],
                    colWidths=[_ic_box_size],
                    rowHeights=[_ic_box_size]
                )
                _ic_image_cell.setStyle(TableStyle([
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ]))

            # Cellule droite : la checklist (basée sur lignes)
            _ic_check_rows = []
            for lg in lignes:
                val = (lg.get('valeur') or '').strip().lower()
                done = val in ('1', 'true', 'oui', 'yes', 'on', 'x')
                libelle_esc = _xml_esc_m(lg.get("libelle", ""))
                if done:
                    box = '<font name="Helvetica-Bold" size="11" color="#10B981">&#10003;</font>'
                else:
                    box = '<font name="Helvetica-Bold" size="11" color="#cbd5e1">&#9744;</font>'
                _ic_check_rows.append([
                    Paragraph(f'{box}&nbsp;&nbsp;<font color="#0F172A" size="9">{libelle_esc}</font>', styles['Normal'])
                ])
            if not _ic_check_rows:
                _ic_check_rows.append([
                    Paragraph('<i><font color="#94a3b8" size="9">Aucun item dans la checklist</font></i>', styles['Normal'])
                ])
            _ic_check_table = Table(_ic_check_rows, colWidths=[_ic_right_w - 8])
            _ic_check_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
            ]))

            # Combinaison image | checklist
            _ic_outer_table = Table([[_ic_image_cell, _ic_check_table]],
                                     colWidths=[_ic_left_w, _ic_right_w])
            _ic_outer_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                ('LINEAFTER', (0, 0), (0, -1), 0.5, BORDER),
            ]))
            story.append(KeepTogether([
                _section_title(bloc_nom.upper(), styles, _avail_w, icon=bloc.get("icon")),
                _ic_outer_table,
            ]))
            story.append(Spacer(1, _sect_gap))

        elif bloc_type == 'image':
            # Source actuelle : image principale de l'équipement (passée via data['equipement_image_path'])
            # v217.3 : pas de titre/bandeau pour ce type de module — on affiche directement l'image
            img_path = data.get('equipement_image_path')
            if img_path and os.path.exists(img_path):
                try:
                    from reportlab.platypus import Image as RLImage
                    from PIL import Image as PILImageLib
                    # Lire les dimensions pour conserver le ratio
                    with PILImageLib.open(img_path) as pim:
                        iw, ih = pim.size
                    # Hauteur cible : adapter selon largeur dispo
                    # Mode demi (8.3cm) : hauteur max 6cm ; Mode pleine (17cm) : hauteur max 10cm
                    max_h = 6*cm if _avail_w < 12*cm else 10*cm
                    target_w = _avail_w
                    target_h = target_w * (ih / iw) if iw > 0 else max_h
                    if target_h > max_h:
                        target_h = max_h
                        target_w = target_h * (iw / ih) if ih > 0 else _avail_w
                    rl_img = RLImage(img_path, width=target_w, height=target_h)
                    # Wrapper dans Table pour alignement gauche cohérent
                    img_tbl = Table([[rl_img]], colWidths=[_avail_w])
                    img_tbl.setStyle(TableStyle([
                        ('BOX', (0,0), (-1,-1), 0.5, BORDER),
                        ('LEFTPADDING', (0,0), (-1,-1), 4),
                        ('RIGHTPADDING', (0,0), (-1,-1), 4),
                        ('TOPPADDING', (0,0), (-1,-1), 4),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ]))
                    story.append(img_tbl)
                except Exception as e:
                    # Fallback texte si problème
                    placeholder = Table([[Paragraph(f'<i><font color="#94a3b8">Image indisponible ({e})</font></i>', styles["Normal"])]],
                                        colWidths=[_avail_w])
                    placeholder.setStyle(TableStyle([
                        ('BOX', (0,0), (-1,-1), 0.5, BORDER),
                        ('LEFTPADDING', (0,0), (-1,-1), 8),
                        ('RIGHTPADDING', (0,0), (-1,-1), 8),
                        ('TOPPADDING', (0,0), (-1,-1), 16),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
                        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ]))
                    story.append(placeholder)
            else:
                # Pas d'image associée → message
                placeholder = Table([[Paragraph('<i><font color="#94a3b8">Aucune image associée à cet équipement</font></i>', styles["Normal"])]],
                                    colWidths=[_avail_w])
                placeholder.setStyle(TableStyle([
                    ('BOX', (0,0), (-1,-1), 0.5, BORDER),
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
                    ('LEFTPADDING', (0,0), (-1,-1), 8),
                    ('RIGHTPADDING', (0,0), (-1,-1), 8),
                    ('TOPPADDING', (0,0), (-1,-1), 24),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 24),
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ]))
                story.append(placeholder)
            story.append(Spacer(1, _sect_gap))

    # v213 — Si une paire 'demi' n'a pas été fermée à la fin de la boucle, le faire maintenant
    if _pending_pair_close:
        _close_pair_into(_real_story_modules, _sub_left, _sub_right)
        _pending_pair_close = False
        story = _real_story_modules

    # ═════════ MATÉRIEL(S) UTILISÉ(S) ═════════
    # Consolidation de tous les matériels, toutes les lignes (même en doublon)
    materiels = data.get('materiels_globaux') or []
    if materiels:
        mat_rows = [["Désignation", "Quantité"]]
        for m in materiels:
            qte = m.get('quantite', 0)
            try:
                qte_f = float(qte)
                qte_str = f"{int(qte_f)}" if qte_f == int(qte_f) else f"{qte_f:g}"
            except Exception:
                qte_str = str(qte)
            mat_rows.append([m.get('designation', '—'), qte_str])
        mat_table = Table(mat_rows, colWidths=[14*cm, 3*cm])
        mat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), LIGHT),
            ('TEXTCOLOR', (0, 0), (-1, 0), ACCENT),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
            ('GRID', (0, 0), (-1, -1), 0.3, BORDER),
            ('LINEBELOW', (0, 0), (-1, 0), 0.5, ACCENT),
        ]))
        story.append(KeepTogether([_section_title("MATÉRIEL(S) UTILISÉ(S)", styles), mat_table]))
        story.append(Spacer(1, _sect_gap))

    # ═════════ DÉPLACEMENT (dépannage uniquement) ═════════
    depl_km = 0.0
    depl_nb = 0
    try:
        depl_km = float(data.get('deplacement_km') or 0)
        depl_nb = int(data.get('nb_deplacements') or 0)
    except Exception:
        pass
    if (type_label == 'DEPANNAGE') and (depl_km > 0 or depl_nb > 0):
        km_str = f"{depl_km:g}" if depl_km else "—"
        nb_str = str(depl_nb) if depl_nb else "—"
        total_km = depl_km * depl_nb if (depl_km and depl_nb) else 0
        total_str = f"{total_km:g} km" if total_km else "—"
        depl_table = Table([
            [
                Paragraph(f'<font size="8" color="#64748B"><b>Distance A/R</b></font>', styles['Normal']),
                Paragraph(f'<font size="9" color="#0F172A">{km_str} km</font>', styles['Normal']),
                Paragraph(f'<font size="8" color="#64748B"><b>Nombre de déplacements</b></font>', styles['Normal']),
                Paragraph(f'<font size="9" color="#0F172A">{nb_str}</font>', styles['Normal']),
                Paragraph(f'<font size="8" color="#64748B"><b>Total</b></font>', styles['Normal']),
                Paragraph(f'<font size="9" color="#1E3A8A"><b>{total_str}</b></font>', styles['Normal']),
            ]
        ], colWidths=[2.5*cm, 2.5*cm, 4*cm, 2*cm, 2*cm, 4*cm])
        depl_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ]))
        story.append(KeepTogether([_section_title("DÉPLACEMENT", styles), depl_table]))
        story.append(Spacer(1, _sect_gap))

    # v218.94 : Section CONTRÔLE DES ÉQUIPEMENTS DE SÉCURITÉ retirée du rendu en dur.
    # Les saisies (présent/conforme) restent stockées en BDD mais ne sont plus rendues automatiquement.

    # ═════════ SIGNATURES ═════════
    # Pas affichées en layout maintenance (sur demande utilisateur)
    if not is_maintenance_layout:
        sig_lbl_style = ParagraphStyle(
            'SigLbl', fontSize=8, textColor=ACCENT,
            fontName='Helvetica-Bold', alignment=1
        )
        sig_data = [
            [Paragraph('Pour le client', sig_lbl_style),
             '',
             Paragraph('Pour SOCOM', sig_lbl_style)],
            [' ', '', ' '],
            [Paragraph('<font size="6" color="#64748B">Nom, fonction, signature</font>',
                       ParagraphStyle('sfn', fontSize=6, alignment=1)),
             '',
             Paragraph('<font size="6" color="#64748B">Nom, fonction, signature</font>',
                       ParagraphStyle('sfn', fontSize=6, alignment=1))],
        ]
        sig_table = Table(sig_data, colWidths=[7.5*cm, 2*cm, 7.5*cm], rowHeights=[0.6*cm, 1.5*cm, 0.4*cm])
        sig_table.setStyle(TableStyle([
            ('BOX', (0, 0), (0, -1), 0.5, BORDER),
            ('BOX', (2, 0), (2, -1), 0.5, BORDER),
            ('BACKGROUND', (0, 0), (0, 0), LIGHT),
            ('BACKGROUND', (2, 0), (2, 0), LIGHT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(KeepTogether([
            _section_title("SIGNATURES", styles),
            sig_table,
        ]))

    # Build
    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    buf.seek(0)
    return buf.read()


# ══════════════════════════════════════════════════════════
# BILAN ANNUEL
# ══════════════════════════════════════════════════════════
def generate_bilan_annuel_pdf(data):
    """Génère le PDF du bilan annuel d'un projet."""
    from io import BytesIO
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, KeepTogether, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=2.5*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    h_normal = ParagraphStyle('Normal2', parent=styles['Normal'], fontSize=9, leading=11)
    h_small = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8, leading=10)
    story = []

    def esc(s):
        return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    projet = data.get("projet") or {}
    annee = data.get("annee")
    proj_nom = projet.get("nom") or projet.get("numero_projet") or "—"
    client_nom = projet.get("client_nom") or ""

    # ─── TITRE ───
    title_style = ParagraphStyle('Title', fontSize=20, textColor=ACCENT, fontName='Helvetica-Bold', alignment=1, spaceAfter=10)
    sub_style = ParagraphStyle('Sub', fontSize=12, textColor=colors.HexColor('#64748b'), alignment=1, spaceAfter=4)
    story.append(Paragraph(f'Bilan annuel {annee}', title_style))
    story.append(Paragraph(f'<b>{esc(proj_nom)}</b>' + (f' — {esc(client_nom)}' if client_nom else ''), sub_style))
    if projet.get("numero_projet"):
        story.append(Paragraph(f'Projet n° {esc(projet["numero_projet"])}', sub_style))
    story.append(Spacer(1, 14))

    # ─── LOGO PROJET (v218.10) ───
    # S'il y a un logo associé au projet, on l'affiche centré avant les totaux
    logo_fname = projet.get("logo_filename") or ""
    if logo_fname:
        try:
            from pathlib import Path
            from reportlab.platypus import Image as RLImage
            # BASE_DIR n'est pas accessible ici, on construit le chemin par rapport à ce fichier
            base_dir = Path(__file__).resolve().parent
            logo_path = base_dir / "uploads" / "projet_logos" / logo_fname
            if logo_path.exists():
                # Logo centré, hauteur max 3 cm, largeur max 8 cm (ratio préservé)
                logo_img = RLImage(str(logo_path), width=8*cm, height=3*cm, kind='proportional')
                logo_img.hAlign = 'CENTER'
                story.append(logo_img)
                story.append(Spacer(1, 14))
        except Exception:
            # Si problème de chargement (format non supporté, etc.), on continue sans le logo
            pass

    # ─── TOTAUX ───
    totaux = data.get("totaux") or {}
    cards = [
        ("Total interventions", totaux.get("total", 0)),
        ("Bons correctifs (BC)", totaux.get("depannage", 0)),
        ("Bons préventifs (BP)", totaux.get("maintenance", 0)),
        ("Heures réalisées", f"{data.get('heures',0):.2f} h"),
        ("Terminées", totaux.get("terminees", 0)),
        ("En cours", totaux.get("en_cours", 0)),
    ]
    cells = []
    row = []
    for label, val in cards:
        cell = Table([
            [Paragraph(f'<font size="18" color="#1E3A8A"><b>{esc(val)}</b></font>', h_normal)],
            [Paragraph(f'<font size="9" color="#64748b">{esc(label)}</font>', h_normal)],
        ], colWidths=[5.5*cm], rowHeights=[1*cm, 0.6*cm])
        cell.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 0.5, BORDER),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,0), (-1,-1), colors.white),
        ]))
        row.append(cell)
        if len(row) == 3:
            cells.append(row)
            row = []
    if row:
        while len(row) < 3: row.append('')
        cells.append(row)
    # v218.11 : alignement gauche + largeur 17cm pour matcher les titres de section
    # 3 colonnes de 5.6cm + 0.2cm de gutter = ~17cm (les paddings le dépassent légèrement, OK)
    cards_table = Table(cells, colWidths=[5.65*cm]*3, hAlign='LEFT')
    cards_table.setStyle(TableStyle([
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    # v218.13 : KeepTogether pour ne pas couper le titre du tableau
    story.append(KeepTogether([_section_title("VUE D'ENSEMBLE", styles), cards_table]))
    story.append(Spacer(1, 14))

    # ─── RÉPARTITION PAR TECHNIQUE ───
    par_tech = data.get("par_technique") or []
    if par_tech:
        rows_t = [['Technique', 'Nombre', '% du total']]
        total_iv = sum(r["nb"] for r in par_tech) or 1
        for r in par_tech:
            pct = round(100 * r["nb"] / total_iv)
            rows_t.append([
                Paragraph(esc(r.get("technique","") or "—"), h_normal),
                Paragraph(str(r["nb"]), h_normal),
                Paragraph(f'{pct}%', h_normal),
            ])
        # v218.11 : largeur 17cm pour matcher la largeur des titres de section
        t = Table(rows_t, colWidths=[8.5*cm, 4*cm, 4.5*cm], hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.4, BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(KeepTogether([_section_title("RÉPARTITION PAR TECHNIQUE", styles), t]))
        story.append(Spacer(1, 10))

    # ─── ÉVOLUTION MENSUELLE ───
    par_mois = data.get("par_mois") or []
    if par_mois:
        mois_labels = ['Jan','Fév','Mar','Avr','Mai','Jun','Jul','Aoû','Sep','Oct','Nov','Déc']
        # Tableau mois × (BC, BP, Total)
        rows_m = [['Mois', 'BC', 'BP', 'Total']]
        for r in par_mois:
            t = (r["bc"] or 0) + (r["bp"] or 0)
            rows_m.append([
                Paragraph(mois_labels[r["mois"]-1], h_normal),
                Paragraph(str(r["bc"] or 0), h_normal),
                Paragraph(str(r["bp"] or 0), h_normal),
                Paragraph(f'<b>{t}</b>', h_normal),
            ])
        # Ligne de totaux
        tot_bc = sum((r["bc"] or 0) for r in par_mois)
        tot_bp = sum((r["bp"] or 0) for r in par_mois)
        rows_m.append([
            Paragraph('<b>TOTAL</b>', h_normal),
            Paragraph(f'<b>{tot_bc}</b>', h_normal),
            Paragraph(f'<b>{tot_bp}</b>', h_normal),
            Paragraph(f'<b>{tot_bc+tot_bp}</b>', h_normal),
        ])
        # v218.11 : largeur 17cm pour matcher la largeur des titres de section
        tm = Table(rows_m, colWidths=[4.25*cm, 4.25*cm, 4.25*cm, 4.25*cm], hAlign='LEFT')
        tm.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.4, BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.white, LIGHT]),
            ('BACKGROUND', (0,-1), (-1,-1), LIGHT),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,1), (-1,-1), 'CENTER'),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(KeepTogether([_section_title("ÉVOLUTION MOIS PAR MOIS", styles), tm]))
        story.append(Spacer(1, 10))

    # ─── COMPLÉTION GAMMES BP ───
    completion_bp = data.get("completion_bp") or []
    if completion_bp:
        rows_c = [['Bon', 'Équipement', 'Date', 'Opérations', '%']]
        for c in completion_bp:
            rows_c.append([
                Paragraph(esc(c["numero"]), h_normal),
                Paragraph(esc(c["equipement"]), h_normal),
                Paragraph(esc(c["date"]), h_normal),
                Paragraph(f'{c["nb_done"]} / {c["nb_ops"]}', h_normal),
                Paragraph(f'<b>{c["pct"]}%</b>', h_normal),
            ])
        # v218.11 : largeur 17cm pour matcher la largeur des titres de section
        tc = Table(rows_c, colWidths=[2.5*cm, 7*cm, 2.5*cm, 2.5*cm, 2.5*cm], hAlign='LEFT')
        tc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.4, BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        # v218.13 : éviter que le titre soit séparé du tableau (mais autoriser la coupure si trop long)
        story.append(KeepTogether([_section_title("COMPLÉTION DES GAMMES DE MAINTENANCE PRÉVENTIVE", styles), tc]))
        story.append(Spacer(1, 10))

    # ─── ÉQUIPEMENTS CONCERNÉS ───
    equipements = data.get("equipements") or []
    if equipements:
        # v218.14 : pas de saut de page, enchaînement naturel
        story.append(_section_title("ÉQUIPEMENTS CONCERNÉS", styles))
        for eq in equipements:
            iv_count = len(eq.get("interventions") or [])
            eq_title = Paragraph(
                f'<font size="11" color="#1E3A8A"><b>{esc(eq["designation"])}</b></font>'
                + f' <font size="9" color="#64748b">— {esc(eq.get("type_technique","") or "")} '
                + (f'({esc(eq.get("localisation",""))})' if eq.get("localisation") else '')
                + f' — {iv_count} intervention(s)</font>',
                h_normal
            )
            iv_rows = [['N°', 'Type', 'Statut', 'Date', 'CR']]
            for iv in (eq.get("interventions") or []):
                iv_rows.append([
                    Paragraph(esc(iv.get("numero","")), h_small),
                    Paragraph(esc(iv.get("type","")), h_small),
                    Paragraph(esc(iv.get("statut","")), h_small),
                    Paragraph(esc(iv.get("date_realisation") or iv.get("date_prevue") or ""), h_small),
                    Paragraph(str(iv.get("nb_cr",0)), h_small),
                ])
            # v218.11 : largeur 17cm + alignement gauche
            iv_table = Table(iv_rows, colWidths=[3*cm, 4*cm, 4*cm, 4*cm, 2*cm], hAlign='LEFT')
            iv_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), LIGHT),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.3, BORDER),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('LEFTPADDING', (0,0), (-1,-1), 4),
                ('RIGHTPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 2),
                ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ]))
            story.append(KeepTogether([eq_title, Spacer(1, 3), iv_table, Spacer(1, 8)]))

    # ─── LISTE COMPLÈTE INTERVENTIONS ───
    interventions = data.get("interventions") or []
    if interventions:
        rows_i = [['N°', 'Type', 'Équipement', 'Date', 'Tech.', 'CR', 'Heures']]
        for iv in interventions:
            rows_i.append([
                Paragraph(esc(iv.get("numero","")), h_small),
                Paragraph(esc(iv.get("type","")), h_small),
                Paragraph(esc(iv.get("equipement","")), h_small),
                Paragraph(esc(iv.get("date_realisation") or iv.get("date_prevue") or ""), h_small),
                Paragraph(esc(iv.get("technicien_nom","") or "—"), h_small),
                Paragraph(str(iv.get("nb_cr",0)), h_small),
                Paragraph(f'{iv.get("heures",0):.1f}h' if iv.get("heures") else "—", h_small),
            ])
        # v218.15 : largeur 17cm + alignement gauche pour matcher le titre
        ti = Table(rows_i, colWidths=[2*cm, 2*cm, 5.5*cm, 2.2*cm, 2.5*cm, 1.3*cm, 1.5*cm], hAlign='LEFT')
        ti.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7.5),
            ('GRID', (0,0), (-1,-1), 0.3, BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 3),
            ('RIGHTPADDING', (0,0), (-1,-1), 3),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ]))
        # v218.15 : header répété si le tableau s'étale sur plusieurs pages
        ti.repeatRows = 1
        # KeepTogether pour garder le titre avec au moins le début du tableau
        story.append(KeepTogether([_section_title("LISTE COMPLÈTE DES INTERVENTIONS", styles), ti]))

    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    buf.seek(0)
    return buf.read()
