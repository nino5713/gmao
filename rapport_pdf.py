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
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, KeepTogether, PageBreak
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


def _draw_header_footer(canvas, doc):
    """En-tête sobre (logo à gauche + N° bon et date à droite + trait bleu) + pied de page."""
    canvas.saveState()
    W, H = A4
    # Logo SOCOM en haut à gauche
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
    # N° de bon + date à droite (stockés par generate_rapport dans doc._header_info)
    header_info = getattr(doc, '_header_info', None) or {}
    numero = header_info.get('numero_iv', '') or ''
    date_iv = header_info.get('date', '') or ''
    if numero or date_iv:
        canvas.setFont('Helvetica-Bold', 11)
        canvas.setFillColor(ACCENT)
        parts = []
        if numero: parts.append(numero)
        if date_iv: parts.append(date_iv)
        canvas.drawRightString(W - 1.2*cm, H - 1.3*cm, "  —  ".join(parts))
    # Trait bleu sous l'en-tête
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(1.5)
    canvas.line(1.5*cm, H - 1.8*cm, W - 1.5*cm, H - 1.8*cm)
    # Numéro de page en pied
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(W - 1.5*cm, 1*cm, f"Page {doc.page}")
    canvas.drawString(1.5*cm, 1*cm, "SOCOM S.A. — 10 rue du Commerce — L-3895 FOETZ")
    canvas.restoreState()


def _section_title(text, styles):
    """Titre de section : texte blanc sur fond bleu foncé SOCOM.
    Rendu via un Table 17cm de large pour garantir l'alignement avec les tableaux de données
    qui suivent (évite le débordement latéral dû à borderPadding sur Paragraph).
    """
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
    tbl = Table([[para]], colWidths=[17*cm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), ACCENT),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    return tbl


def _section_title_with_icon(text, icon_path, styles):
    """v218.208 : variante de _section_title avec icône PNG à gauche du titre.
    L'icône est rendue à 0.6cm de large, le texte prend le reste.
    Si icon_path est None / invalide → fallback sur _section_title sans icône.
    """
    if not icon_path or not os.path.exists(icon_path):
        return _section_title(text, styles)
    try:
        from reportlab.lib.utils import ImageReader
        icon_w = 0.6 * cm
        # Calculer la hauteur de l'icône pour conserver le ratio (v218.196)
        _ir = ImageReader(icon_path)
        _iw, _ih = _ir.getSize()
        if _iw and _ih:
            icon_h = icon_w * (_ih / float(_iw))
        else:
            icon_h = icon_w
        # Limite la hauteur pour ne pas faire exploser la barre de titre
        if icon_h > 0.7 * cm:
            icon_h = 0.7 * cm
            icon_w = icon_h * (_iw / float(_ih)) if _ih else icon_w
        img = Image(icon_path, width=icon_w, height=icon_h)
    except Exception:
        return _section_title(text, styles)

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
    # Table 2 colonnes : icône (0.9cm box) | texte (16.1cm) = 17cm total
    tbl = Table([[img, para]], colWidths=[0.9*cm, 16.1*cm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), ACCENT),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (0, 0), 6),
        ('RIGHTPADDING', (0, 0), (0, 0), 2),
        ('LEFTPADDING', (1, 0), (1, 0), 4),
        ('RIGHTPADDING', (1, 0), (1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return tbl


def _module_icon_path(icon_slug):
    """v218.208 : résout un slug Heroicons en chemin absolu vers le PNG dans icons/modules/.
    Retourne None si le slug est vide ou si le fichier n'existe pas.
    """
    if not icon_slug:
        return None
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(base, "icons", "modules", f"{icon_slug}.png")
        if os.path.exists(candidate):
            return candidate
    except Exception:
        pass
    return None


def _info_row(label, value, styles):
    """Ligne étiquette/valeur pour bloc 'Informations générales'."""
    return [
        Paragraph(f'<font color="#64748B" size="8"><b>{label}</b></font>', styles['Normal']),
        Paragraph(f'<font color="#0F172A" size="9">{value or "—"}</font>', styles['Normal']),
    ]


# v218.191 : labels lisibles des champs dynamiques pour info_box
_COVER_FIELD_LABELS = {
    "client": "Client", "projet": "Projet", "numero_projet": "N° projet",
    "numero_iv": "N° intervention", "numero_bon": "N° bon", "date": "Date",
    "technique": "Technique", "sous_type": "Sous-type", "equipement": "Équipement",
    "marque_modele": "Marque / Modèle", "localisation": "Localisation",
    "intervenants": "Intervenants", "responsable": "Responsable",
    "type_label": "Type", "puissance": "Puissance", "numero_serie": "N° série",
    # v218.198
    "heure_debut": "Heure de début", "heure_fin": "Heure de fin",
    "technicien": "Technicien(s)",
}


def _format_projet(data):
    """v218.197 : retourne 'N° — Nom' si les 2 existent, sinon l'un ou l'autre."""
    num = (data.get("numero_projet") or "").strip()
    nom = (data.get("projet_nom") or "").strip()
    if num and num != "—" and nom:
        return f"{num} — {nom}"
    if num and num != "—":
        return num
    if nom:
        return nom
    return ""


def _interp_text(text, data):
    """Remplace {field} par la valeur correspondante dans data (chaîne).
    v218.192 : aliase aussi 'projet' → projet_nom, 'equipement' → designation, etc."""
    if not text:
        return ""
    out = str(text)
    # Aliases utiles (cohérents avec _COVER_DYNAMIC_FIELDS de app.py)
    aliases = _build_field_map(data)
    for k, v in aliases.items():
        if isinstance(v, (str, int, float)):
            out = out.replace("{" + k + "}", str(v) if v is not None else "")
    return out


def _build_field_map(data):
    """v218.192 : construit le mapping clé → valeur lisible pour info_box."""
    eq = data.get("equipement") or {}
    if not isinstance(eq, dict): eq = {}
    return {
        # Aliases UI → données
        "client": data.get("client") or "",
        # v218.197 : projet = "n° — nom" comme côté backend pour la section figée
        "projet": _format_projet(data),
        "numero_projet": data.get("numero_projet") or "",
        "numero_iv": data.get("numero_iv") or "",
        "numero_bon": data.get("numero_iv") or "",
        "date": data.get("date") or "",
        "technique": data.get("technique") or "",
        "sous_type": data.get("sous_type") or "",
        "equipement": (eq.get("designation") if isinstance(eq, dict) else "") or data.get("equip_nom") or "",
        "marque_modele": data.get("marque_modele") or "",
        "localisation": data.get("localisation") or "",
        "type_label": data.get("type_label") or "",
        "puissance": (eq.get("puissance") if isinstance(eq, dict) else "") or "",
        "numero_serie": (eq.get("numero_serie") if isinstance(eq, dict) else "") or "",
        "technicien": data.get("intervenants") or data.get("technicien_nom") or "",
        # v218.198/v218.200 : heures (planifiée ou réelle)
        "heure_debut": data.get("heure_debut_reel") or data.get("heure_prevue") or "",
        "heure_fin": data.get("heure_fin_reel") or "",
    }


def _render_cover_blocks_dynamic(cover_blocks, data, styles):
    """Construit la story de la page de garde à partir des blocs paramétrés.
    Retourne une liste d'éléments Flowable à insérer dans le PDF.
    """
    story = []
    if not cover_blocks:
        return story

    def _xml_esc(s):
        if s is None: return ''
        return (str(s)
                .replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                .replace('"', '&quot;').replace("'", '&#39;'))

    for b in cover_blocks:
        if not isinstance(b, dict): continue
        t = b.get("type")

        if t == "spacer":
            hcm = float(b.get("height_cm") or 0.5)
            story.append(Spacer(1, hcm * cm))

        elif t == "separator":
            color_str = b.get("color") or "#CBD5E1"
            try: col = colors.HexColor(color_str)
            except Exception: col = BORDER
            th = float(b.get("thickness") or 0.5)
            line_tbl = Table([['']], colWidths=[17*cm], rowHeights=[2])
            line_tbl.setStyle(TableStyle([
                ('LINEABOVE', (0, 0), (-1, 0), th, col),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
            story.append(line_tbl)
            story.append(Spacer(1, 4))

        elif t in ("title", "subtitle", "text"):
            txt = _xml_esc(_interp_text(b.get("text"), data))
            if not txt.strip(): continue
            fs = int(b.get("font_size") or (24 if t == "title" else 18 if t == "subtitle" else 11))
            color_str = b.get("color") or "#1E3A8A"
            try: col = colors.HexColor(color_str)
            except Exception: col = ACCENT
            align = b.get("align") or "center"
            align_map = {"left": 0, "center": 1, "right": 2}
            bold = b.get("bold", True if t in ("title", "subtitle") else False)
            tag_o, tag_c = ("<b>", "</b>") if bold else ("", "")
            ps = ParagraphStyle(
                f"Cover_{t}", parent=styles['Normal'],
                fontSize=fs, leading=int(fs * 1.2),
                textColor=col, alignment=align_map.get(align, 1),
                spaceAfter=6,
            )
            story.append(Paragraph(f"{tag_o}{txt}{tag_c}", ps))

        elif t == "image":
            if b.get("use_projet_logo") and data.get("projet_logo_path"):
                path = data["projet_logo_path"]
            else:
                path = b.get("path") or ""
                if path and not os.path.isabs(path):
                    # Tenter chemin relatif au répertoire app (BASE_DIR)
                    try:
                        base = os.path.dirname(os.path.abspath(__file__))
                        candidate = os.path.join(base, path)
                        if os.path.exists(candidate):
                            path = candidate
                    except Exception: pass
            if path and os.path.exists(path):
                try:
                    w = float(b.get("width_cm") or 8) * cm
                    # v218.196 : calculer ratio avec ImageReader
                    from reportlab.lib.utils import ImageReader
                    try:
                        _ir = ImageReader(path)
                        _iw, _ih = _ir.getSize()
                        if _iw and _ih:
                            h_calc = w * (_ih / float(_iw))
                            img = Image(path, width=w, height=h_calc)
                        else:
                            img = Image(path, width=w)
                    except Exception:
                        img = Image(path, width=w)
                    align = b.get("align") or "center"
                    align_map = {"left": "LEFT", "center": "CENTER", "right": "RIGHT"}
                    img_tbl = Table([[img]], colWidths=[17*cm])
                    img_tbl.setStyle(TableStyle([
                        ('ALIGN', (0, 0), (-1, -1), align_map.get(align, "CENTER")),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ]))
                    story.append(img_tbl)
                except Exception as _eimg:
                    try:
                        import sys
                        sys.stderr.write(f"[PDF image ERR] path={path!r} err={_eimg!r}\n")
                        sys.stderr.flush()
                    except Exception: pass

        elif t == "equipment_image":
            # v218.185 : photo de l'équipement transmise via data["equipment_image_path"]
            # v218.193 : accepter aussi la clé française "equipement_image_path"
            path = (data.get("equipment_image_path") 
                    or data.get("equipement_image_path") or "")
            if path and os.path.exists(path):
                try:
                    w = float(b.get("width_cm") or 10) * cm
                    # v218.196 : utiliser ImageReader pour calculer le ratio sans kind='proportional'
                    from reportlab.lib.utils import ImageReader
                    try:
                        _ir = ImageReader(path)
                        _iw, _ih = _ir.getSize()
                        if _iw and _ih:
                            h_calc = w * (_ih / float(_iw))
                            img = Image(path, width=w, height=h_calc)
                        else:
                            img = Image(path, width=w)
                    except Exception:
                        img = Image(path, width=w)
                    align = b.get("align") or "center"
                    align_map = {"left": "LEFT", "center": "CENTER", "right": "RIGHT"}
                    img_tbl = Table([[img]], colWidths=[17*cm])
                    img_tbl.setStyle(TableStyle([
                        ('ALIGN', (0, 0), (-1, -1), align_map.get(align, "CENTER")),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ]))
                    story.append(img_tbl)
                except Exception as _eimg:
                    # v218.195 : log explicite pour identifier le souci
                    try:
                        import sys
                        sys.stderr.write(f"[PDF equipment_image ERR] path={path!r} err={_eimg!r}\n")
                        sys.stderr.flush()
                    except Exception: pass

        elif t == "info_box":
            title = b.get("title") or "INFORMATIONS GÉNÉRALES"
            fields = b.get("fields") or []
            if not fields: continue
            field_map = _build_field_map(data)
            rows_data = []
            for f in fields:
                lbl = _COVER_FIELD_LABELS.get(f, f)
                val = field_map.get(f, "")
                if val is None: val = ""
                rows_data.append(_info_row(lbl, _xml_esc(val), styles))
            info_tbl = Table(rows_data, colWidths=[5*cm, 12*cm])
            info_tbl.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
                ('BACKGROUND', (0, 0), (0, -1), LIGHT),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(KeepTogether([_section_title(title, styles), info_tbl]))
            story.append(Spacer(1, 6))

        elif t == "gamme_maintenance":
            # v218.212 : rendu de la gamme de maintenance dans la page de garde
            # → opérations cochables + tableau des sous-équipements concernés
            title = b.get("title") or "OPÉRATIONS DE LA GAMME DE MAINTENANCE"
            gamme_ops_list = data.get('gamme_operations') or []
            gamme_sub = data.get('gamme_maintenance') or []
            any_ops = any((g.get('operations') or []) for g in gamme_ops_list)
            if not any_ops and not gamme_sub:
                # Aucune donnée : on saute le bloc plutôt que d'afficher un cadre vide
                continue
            # Bloc opérations
            check_rows = []
            for g in gamme_ops_list:
                ops = g.get('operations') or []
                if not ops:
                    continue
                if len(gamme_ops_list) > 1 and g.get('gamme_nom'):
                    check_rows.append([
                        Paragraph(
                            f'<font color="#1E3A8A"><b>{_xml_esc(g["gamme_nom"])}</b></font>',
                            styles['Normal']
                        ),
                    ])
                for op in ops:
                    if isinstance(op, dict):
                        desc = op.get('description', '') or ''
                        done = op.get('done', False)
                    else:
                        desc = str(op)
                        done = False
                    if done:
                        box = '<font name="Helvetica-Bold" size="11" color="#10B981">☑</font>'
                        check_rows.append([
                            Paragraph(
                                f'{box}&nbsp;&nbsp;{_xml_esc(desc)}',
                                styles['Normal']
                            )
                        ])
                    else:
                        check_rows.append([
                            Paragraph(
                                f'<font name="Helvetica" size="11">☐</font>&nbsp;&nbsp;{_xml_esc(desc)}',
                                styles['Normal']
                            )
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
                story.append(KeepTogether([_section_title(title, styles), check_table]))
                story.append(Spacer(1, 6))
            # Tableau des sous-équipements (si présents)
            if gamme_sub:
                sub_rows = [['Sous-équipement', 'Localisation', 'Date de réalisation', 'CR']]
                for g in gamme_sub:
                    nom = g.get('nom', '') or '—'
                    loc = g.get('localisation', '') or ''
                    dt = g.get('date_realisation', '') or '—'
                    num = g.get('cr_numero', '') or ''
                    sub_rows.append([
                        Paragraph(_xml_esc(nom), styles['Normal']),
                        Paragraph(_xml_esc(loc), styles['Normal']),
                        Paragraph(_xml_esc(dt), styles['Normal']),
                        Paragraph(_xml_esc(num), styles['Normal']),
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
                story.append(Spacer(1, 6))
            # Marquer comme rendu pour éviter le doublon dans la section principale plus bas
            data["_gamme_rendered_in_cover"] = True

        elif t == "observations":
            # v218.212 : observations / commentaires des CR concaténés
            title = b.get("title") or "OBSERVATIONS"
            crs = data.get('comptes_rendus') or []
            # Concaténer les textes observations / commentaires des CR
            obs_parts = []
            for cr in crs:
                txt = (cr.get('observations') or cr.get('commentaire')
                       or cr.get('description') or '').strip()
                if txt:
                    num = cr.get('numero', '') or ''
                    if num:
                        obs_parts.append(f"<b>CR {num}</b><br/>{_xml_esc(txt).replace(chr(10), '<br/>')}")
                    else:
                        obs_parts.append(_xml_esc(txt).replace('\n', '<br/>'))
            if not obs_parts:
                continue
            obs_html = '<br/><br/>'.join(obs_parts)
            obs_para = Paragraph(obs_html, styles['Normal'])
            obs_cell = Table([[obs_para]], colWidths=[17*cm])
            obs_cell.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(KeepTogether([_section_title(title, styles), obs_cell]))
            story.append(Spacer(1, 6))

    return story


# v218.207 : Mapping slug Heroicons (cf. SR_AVAILABLE_ICONS dans index.html) → emoji équivalent.
# Permet d'afficher une icône dans le titre des modules PDF au lieu du slug brut "chart-bar".
_MODULE_ICON_EMOJI = {
    # Énergie / Électrique
    "bolt": "⚡",
    "battery-100": "🔋",
    "fire": "🔥",
    "sparkles": "✨",
    # Outils / Configuration
    "wrench-screwdriver": "🔧",
    "cog-6-tooth": "⚙️",
    "cpu-chip": "🖥️",
    "beaker": "🧪",
    # Données / Mesures
    "chart-bar": "📊",
    "arrow-trending-up": "📈",
    "arrow-trending-down": "📉",
    # Documents / Listes
    "clipboard-document-list": "📋",
    "document-text": "📄",
    "photo": "📷",
    # États / Statut
    "check-circle": "✅",
    "x-circle": "❌",
    "exclamation-triangle": "⚠️",
    "information-circle": "ℹ️",
    "shield-check": "🛡️",
    "bell": "🔔",
    # Temps
    "clock": "🕐",
    "calendar-days": "📅",
    # Environnement
    "sun": "☀️",
    "moon": "🌙",
}


def _build_module_flowables(bloc, width_cm, styles, mk_title):
    """v218.209 : construit la liste des flowables d'un module à la largeur demandée.
    Retourne [title, content_flowable_1, content_flowable_2, ...] ou [] si le module est vide.
    width_cm : largeur disponible en cm (17 pour pleine, ~8.3 pour demi).
    mk_title : callable qui retourne le titre (avec ou sans icône) au format Table 17cm — sera
               retaillé via Table 1-cell pour la largeur demandée si demi.
    v218.211 : si field_options.hide_title === True (module image), on omet le bandeau de titre.
               Le caption (nom de l'image) n'est plus affiché pour les modules image.
    """
    btype = (bloc.get("type") or "tableau").lower()
    lignes = bloc.get("lignes") or []
    flow = []

    # v218.211 : lire les field_options du bloc pour récupérer hide_title
    _bcfg = {}
    try:
        _raw = bloc.get("field_options") or ""
        if _raw:
            if isinstance(_raw, str):
                _bcfg = json.loads(_raw)
            elif isinstance(_raw, dict):
                _bcfg = _raw
    except Exception:
        _bcfg = {}
    _hide_title = bool(_bcfg.get("hide_title"))

    # Titre : recalculer à la bonne largeur si demi — sauf si hide_title coché
    if not _hide_title:
        title_flowable = mk_title(width_cm)
        flow.append(title_flowable)

    if btype in ("tableau", "checklist", "preconisations"):
        if not lignes:
            return []
        # v218.217 : détecter si TOUTES les lignes sont text_pair → on omet l'entête
        # "Libellé / Valeur / Unité" qui n'a pas de sens pour ce type.
        all_text_pair = all(
            (lg.get("field_type") or "numeric").lower() == "text_pair"
            for lg in lignes
        )
        if all_text_pair:
            tbl_data = []
            header_row_offset = 0  # pas de ligne d'entête
        else:
            # Header classique
            tbl_data = [[
                Paragraph('<b><font color="white">Libellé</font></b>', styles['Normal']),
                Paragraph('<b><font color="white">Valeur</font></b>', styles['Normal']),
                Paragraph('<b><font color="white">Unité</font></b>', styles['Normal']),
            ]]
            header_row_offset = 1
        # v218.216 : tracker les indices des lignes text_pair pour appliquer un SPAN après
        pair_row_indices = []
        for lg in lignes:
            lib = str(lg.get("libelle") or "")
            val = str(lg.get("valeur") or "")
            unite = str(lg.get("unite") or "")
            ftype = (lg.get("field_type") or "numeric").lower()

            if ftype == "text_pair":
                # v218.216 : pas de libellé pour text_pair, juste les 2 valeurs côte à côte.
                # On rend une cellule unique qui spannera les 3 colonnes (gérée plus bas).
                parts = (val or "").split("|||")
                v1 = (parts[0] if len(parts) > 0 else "").strip()
                v2 = (parts[1] if len(parts) > 1 else "").strip()
                v1_disp = v1 if v1 else "—"
                v2_disp = v2 if v2 else "—"
                pair_inner = Table(
                    [[
                        Paragraph(f'<font size="9"><b>{v1_disp}</b></font>', styles['Normal']),
                        Paragraph(f'<font size="9"><b>{v2_disp}</b></font>', styles['Normal']),
                    ]],
                    colWidths=[((9 + 5 + 3) * width_cm / 17.0) / 2 * cm] * 2
                )
                pair_inner.setStyle(TableStyle([
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 0),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                    ('LINEAFTER', (0, 0), (0, 0), 0.4, BORDER),
                ]))
                # On met la cellule pair_inner dans la 1ère colonne, vide les 2 autres
                tbl_data.append([pair_inner, '', ''])
                pair_row_indices.append(len(tbl_data) - 1)
            else:
                # Lignes normales : Libellé / Valeur / Unité
                val_disp = val if val else "—"
                tbl_data.append([
                    Paragraph(f'<font size="9">{lib}</font>', styles['Normal']),
                    Paragraph(f'<font size="9"><b>{val_disp}</b></font>', styles['Normal']),
                    Paragraph(f'<font size="9" color="#64748B">{unite}</font>', styles['Normal']),
                ])
        # Colonnes au prorata de width_cm (originalement 9/5/3 sur 17cm)
        ratio = width_cm / 17.0
        tbl = Table(tbl_data, colWidths=[9*cm*ratio, 5*cm*ratio, 3*cm*ratio])
        style_cmds = [
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
        ]
        # v218.217 : si on a une ligne d'entête, l'afficher en bleu + zébrer à partir de la ligne 1
        if not all_text_pair:
            style_cmds.append(('BACKGROUND', (0, 0), (-1, 0), ACCENT))
            style_cmds.append(('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]))
        else:
            # Pas d'entête : zébrer à partir de la première ligne
            style_cmds.append(('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]))
        # v218.216 : fusionner les 3 colonnes pour chaque ligne text_pair
        for r_idx in pair_row_indices:
            style_cmds.append(('SPAN', (0, r_idx), (2, r_idx)))
            # Padding réduit pour que le sous-tableau colle aux bords
            style_cmds.append(('LEFTPADDING', (0, r_idx), (2, r_idx), 0))
            style_cmds.append(('RIGHTPADDING', (0, r_idx), (2, r_idx), 0))
        tbl.setStyle(TableStyle(style_cmds))
        flow.append(tbl)

    elif btype == "mesures_batteries":
        # v218.215 : rendu spécifique du module Mesures batteries.
        # Grille 6 colonnes par chaîne, avec couleur rouge si hors plage (vnom ± tol%).
        chains = bloc.get("chains") or []
        bat_values = bloc.get("bat_values") or {}
        try:
            v_nom = float(_bcfg.get("tension_nominale") or 12.0)
        except Exception:
            v_nom = 12.0
        try:
            tol_pct = float(_bcfg.get("tolerance_pct") or 10.0)
        except Exception:
            tol_pct = 10.0
        seuil_bas = v_nom * (1 - tol_pct / 100.0)
        seuil_haut = v_nom * (1 + tol_pct / 100.0)

        # Bandeau récap config (tension nominale, tolérance, plage)
        recap_html = (
            f'<font size="9" color="#64748B">'
            f'Tension nominale : <b>{v_nom:g} V</b> &nbsp;|&nbsp; '
            f'Tolérance : <b>±{tol_pct:g}%</b> &nbsp;|&nbsp; '
            f'Plage : <b>{seuil_bas:.2f} – {seuil_haut:.2f} V</b>'
            f'</font>'
        )
        flow.append(Paragraph(recap_html, styles['Normal']))
        flow.append(Spacer(1, 4))

        if not chains:
            # Avertissement aucune batterie détectée
            warn = Paragraph(
                '<font size="9" color="#78350F"><i>⚠ Aucune batterie détectée pour cet équipement.</i></font>',
                styles['Normal']
            )
            warn_cell = Table([[warn]], colWidths=[(width_cm - 0.2) * cm])
            warn_cell.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FEF3C7')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#F59E0B')),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            flow.append(warn_cell)
        else:
            NCOLS = 6
            # Calculer la largeur d'une cellule en cm (réserve un petit padding)
            grid_w_cm = width_cm - 0.2  # marge interne
            cell_w_cm = grid_w_cm / NCOLS
            for chain in chains:
                chain_idx = int(chain.get("chain_idx") or 0)
                nb_bat = int(chain.get("nb_batteries") or 0)
                piece_type = str(chain.get("piece_type") or "")
                # Titre de la chaîne
                chain_title_html = (
                    f'<font size="10" color="#1E3A8A"><b>🔋 Chaîne {chain_idx + 1}</b></font> '
                    f'<font size="9" color="#64748B"> — {nb_bat} batterie(s)'
                    + (f' — type : {piece_type}' if piece_type else '')
                    + '</font>'
                )
                flow.append(Paragraph(chain_title_html, styles['Normal']))
                flow.append(Spacer(1, 3))

                # Construire la grille NCOLS colonnes : chaque cellule = "B<pos>\n<valeur> V"
                cells = []
                for pos in range(nb_bat):
                    key = f"chain{chain_idx}_pos{pos + 1}"
                    # Compat avec frontend qui utilise pos = 0..N-1 (sans +1) : essayer les 2
                    val_raw = bat_values.get(key)
                    if val_raw is None:
                        val_raw = bat_values.get(f"chain{chain_idx}_pos{pos}")
                    val_str = ""
                    try:
                        if val_raw is not None and str(val_raw).strip() != "":
                            v = float(str(val_raw).replace(",", ".").strip())
                            val_str = f"{v:.2f}"
                        else:
                            v = None
                    except Exception:
                        v = None
                        val_str = str(val_raw or "")
                    # Couleur selon plage
                    if v is None or val_str == "":
                        bg_color = colors.HexColor('#F8FAFC')
                        txt_color = '#94A3B8'
                        val_html = '—'
                    elif v < seuil_bas or v > seuil_haut:
                        bg_color = colors.HexColor('#FEE2E2')
                        txt_color = '#991B1B'
                        val_html = f'{val_str} V'
                    else:
                        bg_color = colors.HexColor('#DCFCE7')
                        txt_color = '#166534'
                        val_html = f'{val_str} V'
                    cell_html = (
                        f'<para align="center">'
                        f'<font size="7" color="#64748B"><b>B{pos + 1}</b></font><br/>'
                        f'<font size="9" color="{txt_color}"><b>{val_html}</b></font>'
                        f'</para>'
                    )
                    cells.append((Paragraph(cell_html, styles['Normal']), bg_color))

                # Découper en lignes de NCOLS
                rows_data = []
                row_styles = []  # (row_idx, col_idx, bg_color)
                for row_start in range(0, len(cells), NCOLS):
                    row_cells = cells[row_start:row_start + NCOLS]
                    # Compléter à NCOLS si dernière ligne incomplète
                    while len(row_cells) < NCOLS:
                        row_cells.append((Paragraph('', styles['Normal']), None))
                    rows_data.append([c[0] for c in row_cells])
                    for col_idx, (_, bg) in enumerate(row_cells):
                        if bg is not None:
                            row_styles.append((len(rows_data) - 1, col_idx, bg))
                bat_tbl = Table(rows_data, colWidths=[cell_w_cm * cm] * NCOLS)
                style_cmds = [
                    ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 3),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 3),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]
                for r, c, bg in row_styles:
                    style_cmds.append(('BACKGROUND', (c, r), (c, r), bg))
                bat_tbl.setStyle(TableStyle(style_cmds))
                flow.append(bat_tbl)
                flow.append(Spacer(1, 6))

    elif btype == "texte":
        txt = ""
        if lignes:
            txt = (lignes[0].get("valeur") or "").strip()
        if txt:
            p = Paragraph(f'<font size="10">{txt}</font>', styles['Normal'])
            flow.append(p)
        else:
            return []  # texte vide → pas afficher

    elif btype == "graphique":
        png = bloc.get("graph_png")
        if png:
            try:
                # v218.196 : éviter kind='proportional', utiliser ImageReader
                from reportlab.lib.utils import ImageReader
                bio = io.BytesIO(png)
                _ir = ImageReader(bio)
                _iw, _ih = _ir.getSize()
                w = (width_cm - 2) * cm  # marge interne
                if _iw and _ih:
                    h_calc = w * (_ih / float(_iw))
                else:
                    h_calc = w * 0.6
                img = Image(io.BytesIO(png), width=w, height=h_calc)
                flow.append(img)
            except Exception:
                return []
        else:
            return []

    elif btype == "image":
        # v218.209 : Image principale de l'équipement
        # v218.211 : on n'affiche plus le nom de l'image en légende
        img_path = bloc.get("equipement_image_path") or ""
        if img_path and os.path.exists(img_path):
            try:
                from reportlab.lib.utils import ImageReader
                w = (width_cm - 2) * cm
                _ir = ImageReader(img_path)
                _iw, _ih = _ir.getSize()
                if _iw and _ih:
                    h_calc = w * (_ih / float(_iw))
                    # Limiter la hauteur pour rester raisonnable
                    max_h = 12 * cm if width_cm >= 15 else 8 * cm
                    if h_calc > max_h:
                        h_calc = max_h
                        w = h_calc * (_iw / float(_ih))
                else:
                    h_calc = w * 0.7
                img = Image(img_path, width=w, height=h_calc)
                flow.append(img)
            except Exception:
                return []
        else:
            # Aucune image : afficher un placeholder discret
            p = Paragraph(
                '<font size="9" color="#92400E"><i>⚠ Aucune image associée à cet équipement</i></font>',
                styles['Normal']
            )
            flow.append(p)

    elif btype == "equipement":
        # v218.209 : Tableau des champs équipement
        eq_data = bloc.get("equipement_data") or {}
        # Champs principaux à afficher (les mêmes que côté frontend, EQ_FIELDS_GEN_DEF)
        fields_gen = [
            ('designation', 'Désignation'),
            ('marque_modele', 'Marque / Modèle'),
            ('puissance', 'Puissance'),
            ('numero_serie', 'N° de série'),
            ('in_out', 'Int. / Ext.'),
            ('localisation', 'Localisation'),
            ('tableau', 'Tableau / Borne'),
            ('technique', 'Technique'),
            ('date_mise_service', 'Mise en service'),
            ('statut', 'Statut'),
        ]
        # Filtrer : garder seulement les champs non vides (sauf designation toujours)
        active_rows = []
        for slug, label in fields_gen:
            v = (eq_data.get(slug) or '').strip() if isinstance(eq_data.get(slug), str) else str(eq_data.get(slug) or '')
            if slug == 'designation' or (v and v != '—'):
                active_rows.append((label, v or '—'))
        # Champs personnalisés (custom_fields)
        custom_fields = eq_data.get('custom_fields') or {}
        if isinstance(custom_fields, dict):
            for slug, cf in custom_fields.items():
                if not isinstance(cf, dict):
                    continue
                label = cf.get('label') or slug
                val = cf.get('value') or '—'
                active_rows.append((label, val))
        if not active_rows:
            return []
        # Construire le tableau
        tbl_data = []
        for label, val in active_rows:
            tbl_data.append([
                Paragraph(f'<font size="9" color="#64748B">{label}</font>', styles['Normal']),
                Paragraph(f'<font size="9"><b>{val}</b></font>', styles['Normal']),
            ])
        ratio = width_cm / 17.0
        tbl = Table(tbl_data, colWidths=[6*cm*ratio, 11*cm*ratio])
        tbl.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ]))
        flow.append(tbl)

    else:
        # Type non géré (image_checklist, mesures_string, borne_charge…) : fallback liste
        if lignes:
            tbl_data = []
            for lg in lignes:
                lib = str(lg.get("libelle") or "")
                val = str(lg.get("valeur") or "—")
                tbl_data.append([
                    Paragraph(f'<font size="9">{lib}</font>', styles['Normal']),
                    Paragraph(f'<font size="9"><b>{val}</b></font>', styles['Normal']),
                ])
            ratio = width_cm / 17.0
            tbl = Table(tbl_data, colWidths=[10*cm*ratio, 7*cm*ratio])
            tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            flow.append(tbl)
        else:
            return []

    return flow


def _render_modules_mesures(mesures_techniques, styles):
    """v218.192 : rend les modules de mesures (technique × sous-type) dans le PDF.
    v218.207 : ignore les slugs Heroicons (Helvetica ne rend pas les emojis).
    v218.208 : si une icône PNG existe pour le slug dans icons/modules/, l'affiche.
    v218.209 : support types 'image' et 'equipement' + groupage côte à côte des modules largeur='demi'.
    Retourne une liste de Flowables."""
    story = []
    if not mesures_techniques:
        return story

    def _make_mk_title(bloc):
        """Retourne un callable qui construit le titre du bloc à la largeur demandée."""
        nom = bloc.get("nom") or "MODULE"
        icon_slug = (bloc.get("icon") or "").strip()
        icon_path = _module_icon_path(icon_slug) if icon_slug else None
        def _mk(width_cm):
            # Si on est en demi, on enveloppe le titre dans un Table 1-cell de la bonne largeur
            full = _section_title_with_icon(nom, icon_path, styles) if icon_path else _section_title(nom, styles)
            if abs(width_cm - 17) < 0.01:
                return full
            # Demi : reconstruire avec colWidth = width_cm
            para = Paragraph(
                f'<font color="#FFFFFF" size="10"><b>{nom}</b></font>',
                ParagraphStyle('SectionTitleDemi', parent=styles['Normal'],
                               fontSize=10, textColor=colors.white, leading=12, leftIndent=0)
            )
            if icon_path:
                try:
                    from reportlab.lib.utils import ImageReader
                    icon_w = 0.6 * cm
                    _ir = ImageReader(icon_path)
                    _iw, _ih = _ir.getSize()
                    icon_h = icon_w * (_ih / float(_iw)) if (_iw and _ih) else icon_w
                    if icon_h > 0.7 * cm:
                        icon_h = 0.7 * cm
                        icon_w = icon_h * (_iw / float(_ih)) if _ih else icon_w
                    img = Image(icon_path, width=icon_w, height=icon_h)
                    tbl = Table([[img, para]], colWidths=[0.9*cm, (width_cm - 0.9)*cm])
                except Exception:
                    tbl = Table([[para]], colWidths=[width_cm*cm])
            else:
                tbl = Table([[para]], colWidths=[width_cm*cm])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), ACCENT),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            return tbl
        return _mk

    # v218.210 : helper pour estimer si un bloc est "lourd" (plus que ~half-page environ)
    # → contient une image, un graphique, ou plus de 20 lignes de tableau.
    # Dans ces cas, on n'essaie PAS de mettre côte à côte (sinon ReportLab plante car la cellule
    # ne peut pas split entre pages dans un Table à 1 ligne).
    def _is_heavy(bloc):
        btype = (bloc.get("type") or "tableau").lower()
        if btype in ("image", "graphique"):
            return True
        if btype == "equipement":
            eq = bloc.get("equipement_data") or {}
            if eq.get("custom_fields"):
                return len(eq.get("custom_fields") or {}) > 15
            return False
        if btype == "mesures_batteries":
            # v218.215 : compter le nombre total de batteries (toutes chaînes confondues).
            # > 18 batteries = > 3 lignes de 6 → considéré comme lourd.
            chains = bloc.get("chains") or []
            total = sum(int(c.get("nb_batteries") or 0) for c in chains)
            return total > 18
        lignes = bloc.get("lignes") or []
        return len(lignes) > 20

    # Itération : on regarde 1 ou 2 modules d'affilée selon largeur
    # v218.213 : on insère un PageBreak avant chaque module dont page_num change
    # par rapport au module précédent (sauf au tout premier).
    i = 0
    n = len(mesures_techniques)
    _prev_page = None
    while i < n:
        bloc = mesures_techniques[i]
        bl_largeur = (bloc.get("largeur") or "pleine").lower()
        cur_page = int(bloc.get("page_num") or 1)

        # v218.213 : saut de page si la page change
        if _prev_page is not None and cur_page != _prev_page:
            story.append(PageBreak())
        _prev_page = cur_page

        # Cas 1 : module demi suivi d'un autre demi → côte à côte
        # v218.210 : seulement si AUCUN des deux n'est "lourd" (sinon crash ReportLab)
        # v218.213 : et seulement si les 2 modules sont sur la MÊME page
        if bl_largeur == "demi" and i + 1 < n:
            bloc2 = mesures_techniques[i + 1]
            bloc2_page = int(bloc2.get("page_num") or 1)
            if ((bloc2.get("largeur") or "pleine").lower() == "demi"
                    and bloc2_page == cur_page
                    and not _is_heavy(bloc) and not _is_heavy(bloc2)):
                # Construire les flowables de chaque module à 8.3cm
                # (17 - 0.4 séparation) / 2 = 8.3
                half_w = 8.3
                mk1 = _make_mk_title(bloc)
                mk2 = _make_mk_title(bloc2)
                flows1 = _build_module_flowables(bloc, half_w, styles, mk1)
                flows2 = _build_module_flowables(bloc2, half_w, styles, mk2)
                if flows1 and flows2:
                    # v218.210 : passer les listes de flowables DIRECTEMENT dans les cellules
                    # (sans KeepTogether qui forçait une hauteur infinie 16777215 → crash).
                    pair = Table([[flows1, flows2]], colWidths=[half_w*cm, half_w*cm])
                    pair.setStyle(TableStyle([
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 0),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                        ('TOPPADDING', (0, 0), (-1, -1), 0),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                        ('LEFTPADDING', (1, 0), (1, 0), 8),  # gap entre colonnes
                    ]))
                    story.append(pair)
                    story.append(Spacer(1, 8))
                    i += 2
                    continue
                elif flows1:
                    story.extend(flows1)
                    story.append(Spacer(1, 8))
                    i += 1
                    continue
                elif flows2:
                    # bloc1 vide, bloc2 demi tout seul → on consomme les 2
                    story.extend(flows2)
                    story.append(Spacer(1, 8))
                    i += 2
                    continue
            # Fallthrough : au moins un est lourd OU les types ne sont pas tous deux demi
            # → on rend bloc en pleine largeur (et bloc2 sera traité au prochain tour)

        # Cas 2 : module pleine largeur OU module demi isolé OU paire abandonnée pour cause de "lourd"
        mk = _make_mk_title(bloc)
        flows = _build_module_flowables(bloc, 17, styles, mk)
        if flows:
            # v218.210 : pas de KeepTogether ici non plus — si le contenu dépasse une page,
            # ReportLab doit pouvoir splitter naturellement (les Table à plusieurs lignes
            # supportent splitByRow, les listes de flowables séparés se posent les uns
            # après les autres en cascadant les pages).
            story.extend(flows)
            story.append(Spacer(1, 8))
        i += 1

    return story


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
    # v218.158 : helper d'échappement XML pour les Paragraph reportlab
    def _xml_esc_local(s):
        if s is None: return ''
        return (str(s)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    # Transmettre les infos au handler d'en-tête (N° bon + date en haut à droite)
    doc._header_info = {
        'numero_iv': data.get('numero_iv', ''),
        'date': data.get('date', ''),
    }

    story = []

    # v218.191 : page de garde DYNAMIQUE depuis cover_page_blocks (paramétrée)
    # Si fournie, on rend la page de garde personnalisée + PageBreak, puis on SAUTE
    # les sections figées (titre, logo sécu, info générales, équipement) et on passe
    # directement aux comptes-rendus.
    _cpb = data.get("cover_page_blocks")
    _use_custom_cover = bool(_cpb and isinstance(_cpb, list) and len(_cpb) > 0)
    if _use_custom_cover:
        # v218.194 : diagnostic des images
        try:
            import sys
            _eq_img = data.get("equipment_image_path") or data.get("equipement_image_path") or ""
            _proj_img = data.get("projet_logo_path") or ""
            _eq_exists = os.path.exists(_eq_img) if _eq_img else False
            _proj_exists = os.path.exists(_proj_img) if _proj_img else False
            sys.stderr.write(f"[PDF cover MES] equipment_image_path={_eq_img!r} exists={_eq_exists}\n")
            sys.stderr.write(f"[PDF cover MES] projet_logo_path={_proj_img!r} exists={_proj_exists}\n")
            sys.stderr.write(f"[PDF cover MES] cover_blocks count={len(_cpb)}\n")
            for _i, _b in enumerate(_cpb):
                sys.stderr.write(f"[PDF cover MES]   block[{_i}] type={_b.get('type')!r} use_projet_logo={_b.get('use_projet_logo')}\n")
            sys.stderr.flush()
        except Exception as _e:
            pass
        story.extend(_render_cover_blocks_dynamic(_cpb, data, styles))
        story.append(PageBreak())

    # ═════════ TITRE ═════════
    type_label = (data.get('type_label') or '').upper()
    if type_label == 'DEPANNAGE':
        titre = "RAPPORT D'INTERVENTION - DÉPANNAGE"
    elif type_label == 'MAINTENANCE':
        titre = "RAPPORT D'INTERVENTION - MAINTENANCE"
    elif type_label == 'MISE_EN_SERVICE':
        titre = "RAPPORT DE MISE EN SERVICE"
    else:
        titre = "RAPPORT D'INTERVENTION"

    # Si on utilise la cover personnalisée, on saute le titre figé + logo sécu + info + équipement
    if not _use_custom_cover:
        story.append(Paragraph(
            f'<b>{titre}</b>',
            ParagraphStyle('Title', fontSize=14, textColor=ACCENT, alignment=1, spaceAfter=6)
        ))

    # ═════════ LOGO SÉCURITÉ (PPSS + EPI) ═════════
    if not _use_custom_cover and os.path.exists(LOGO_SECU):
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
    # v218.191 : marquer le début des sections figées qu'on va supprimer
    # si une page de garde personnalisée est utilisée
    _figées_start_idx = len(story)
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
    story.append(Spacer(1, 6))

    # ═════════ ÉQUIPEMENT CONCERNÉ ═════════
    # Construction dynamique : on n'affiche une ligne que si la donnée est renseignée
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
    story.append(Spacer(1, 6))

    # ═════════ TRANSFORMATEUR (Haute tension uniquement) ═════════
    trafo = data.get('trafo')
    if trafo and any((trafo.get(k) or '').strip() for k in trafo):
        tr_pairs = [
            ('Marque', trafo.get('marque','')),
            ('Année', trafo.get('annee','')),
            ('N° de série', trafo.get('numero_serie','')),
            ('Puissance (kVA)', trafo.get('puissance_kva','')),
            ('Refroidissement', trafo.get('refroidissement','')),
            ('Poids (kg)', trafo.get('poids_kg','')),
            ('Tension d\'entrée (V)', trafo.get('tension_entree_v','')),
            ('Courant (A)', trafo.get('courant_a','')),
            ('Norme', trafo.get('norme','')),
            ('Couplage', trafo.get('couplage','')),
            ('Tension de service (V)', trafo.get('tension_service_v','')),
            ('Réglage tension (kV)', trafo.get('reglage_tension_kv','')),
        ]
        # Ne garder que les champs renseignés
        tr_pairs = [(k, v) for k, v in tr_pairs if (v or '').strip()]
        if tr_pairs:
            tr_rows = []
            for n in range(0, len(tr_pairs), 2):
                left_lbl, left_val = tr_pairs[n]
                right_lbl, right_val = tr_pairs[n+1] if n+1 < len(tr_pairs) else ('', '')
                tr_rows.append([
                    Paragraph(f'<b>{left_lbl}</b>', h_normal), Paragraph(str(left_val), h_normal),
                    Paragraph(f'<b>{right_lbl}</b>', h_normal) if right_lbl else '',
                    Paragraph(str(right_val), h_normal) if right_val else ''
                ])
            tr_table = Table(tr_rows, colWidths=[3.5*cm, 5*cm, 3.5*cm, 5*cm])
            tr_style = [
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
                ('BACKGROUND', (0, 0), (0, -1), LIGHT),
                ('BACKGROUND', (2, 0), (2, -1), LIGHT),
            ]
            tr_table.setStyle(TableStyle(tr_style))
            story.append(KeepTogether([_section_title("TRANSFORMATEUR", styles), tr_table]))
            story.append(Spacer(1, 6))

    # v218.160 : Section CELLULES SUPPRIMÉE (table equipement_cellules DROP).
    # Les données sont maintenant gérées via la section SOUS-ÉQUIPEMENTS ci-dessous.

    # ═════════ SOUS-ÉQUIPEMENTS (v218.158 — toutes techniques) ═════════
    sous_equipements = data.get('sous_equipements') or []
    if sous_equipements:
        se_rows = [[
            Paragraph('<b><font color="white" size="9">Désignation</font></b>', styles['Normal']),
            Paragraph('<b><font color="white" size="9">Marque</font></b>', styles['Normal']),
            Paragraph('<b><font color="white" size="9">Type</font></b>', styles['Normal']),
            Paragraph('<b><font color="white" size="9">Nombre</font></b>', styles['Normal']),
        ]]
        for s in sous_equipements:
            se_rows.append([
                Paragraph(f'<font size="9"><b>{_xml_esc_local(s.get("designation",""))}</b></font>', styles['Normal']),
                Paragraph(f'<font size="9">{_xml_esc_local(s.get("marque","") or "—")}</font>', styles['Normal']),
                Paragraph(f'<font size="9">{_xml_esc_local(s.get("type","") or "—")}</font>', styles['Normal']),
                Paragraph(f'<font size="9" color="#0369A1"><b>{s.get("nombre",1)}</b></font>', styles['Normal']),
            ])
        se_table = Table(se_rows, colWidths=[5.5*cm, 4*cm, 4*cm, 2.5*cm])
        se_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
            ('LINEBELOW', (0, 0), (-1, -1), 0.3, BORDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ]))
        story.append(KeepTogether([_section_title("SOUS-ÉQUIPEMENTS", styles), se_table]))
        story.append(Spacer(1, 6))

    # v218.191 : si une page de garde personnalisée a été rendue,
    # on supprime les sections figées (INFO + ÉQUIPEMENT + TRAFO + CELLULES + SOUS-EQ)
    # ajoutées entre _figées_start_idx et maintenant.
    if _use_custom_cover:
        del story[_figées_start_idx:]

    # v218.192 : pour les bons MISE EN SERVICE, on n'affiche QUE les modules de mesures
    # (pas de descriptif, ni gamme, ni comptes-rendus, ni signatures)
    _is_mes = (type_label == 'MISE_EN_SERVICE')

    # v218.192 : Modules de mesures (CARACTERISTIQUES DE L'UPS, etc.)
    _mesures = data.get('mesures_techniques') or []
    if _mesures:
        story.extend(_render_modules_mesures(_mesures, styles))

    # Pour MES : on s'arrête ici (pas de descriptif, comptes-rendus, signatures)
    if _is_mes:
        doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
        return buf.getvalue()

    # ═════════ DESCRIPTIF (saisi à la création du bon) ═════════
    descriptif = (data.get('description') or '').strip()
    is_maint = data.get('is_maintenance')
    gamme_ops_list = data.get('gamme_operations') or []
    has_gamme_ops = is_maint and any(g.get('operations') for g in gamme_ops_list)
    # v218.212 : si la gamme a déjà été rendue dans la page de garde via le bloc cover
    # 'gamme_maintenance', on ne la rend pas une deuxième fois ici.
    _gamme_already_rendered = bool(data.get('_gamme_rendered_in_cover'))

    if has_gamme_ops and not _gamme_already_rendered:
        # MAINTENANCE : remplacer le descriptif par la liste des opérations en checklist
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
                    box = '<font name="Helvetica-Bold" size="11" color="#10B981">☑</font>'
                    check_rows.append([
                        Paragraph(f'{box}&nbsp;&nbsp;{_xml_esc_d(desc)}', h_normal)
                    ])
                else:
                    check_rows.append([
                        Paragraph(f'<font name="Helvetica" size="11">☐</font>&nbsp;&nbsp;{_xml_esc_d(desc)}', h_normal)
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
            story.append(Spacer(1, 6))

        # Tableau des sous-équipements (sans titre, juste après les opérations)
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
            story.append(Spacer(1, 6))
    elif descriptif and not _gamme_already_rendered:
        # Comportement classique : afficher la description texte
        # v218.212 : skip si la gamme a déjà été rendue dans la page de garde
        # (l'utilisateur a explicitement choisi la gamme via le bloc cover)
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
        story.append(Spacer(1, 6))

    # ═════════ COMPTES-RENDUS D'INTERVENTION ═════════
    # v218.214 : pour les BP MAINTENANCE, on n'affiche PAS les CR ni les signatures
    # (le rapport est centré sur la gamme et les modules de mesures)
    _is_bp_maintenance = (type_label == 'MAINTENANCE')
    crs = data.get('comptes_rendus') or []
    if crs and not _is_bp_maintenance:
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
            if i == 0 and section_title_block is not None:
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
        story.append(Spacer(1, 6))

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
        story.append(Spacer(1, 6))

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
        story.append(Spacer(1, 6))

    # ═════════ CONTRÔLE DES ÉQUIPEMENTS DE SÉCURITÉ (Haute tension) ═════════
    securite_items = data.get('securite_items') or []
    if securite_items:
        from reportlab.platypus import Image as RLImage
        from io import BytesIO
        import base64 as _b64
        def _xml_esc_s(s):
            return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

        def _make_check_cell(label, checked):
            mark = '☒' if checked else '☐'
            color = '#10B981' if checked else '#64748B'
            return Paragraph(f'<font color="{color}" size="11"><b>{mark}</b></font> <font size="8">{label}</font>', h_normal)

        def _build_sec_card(item):
            """Une 'carte' = mini-tableau interne avec photo + libellé + 4 cases."""
            present_val = item.get('present')   # 1, 0 ou None
            conforme_val = item.get('conforme') # 1, 0 ou None
            # Cases : Absent (present==0), Présent (present==1), Conforme (conforme==1), Non conforme (conforme==0)
            absent = (present_val == 0)
            present = (present_val == 1)
            conforme = (conforme_val == 1)
            non_conforme = (conforme_val == 0)
            # Photo
            photo_cell = ''
            photo_data = item.get('photo_data') or ''
            if photo_data:
                try:
                    raw = _b64.b64decode(photo_data)
                    img = RLImage(BytesIO(raw), width=2.8*cm, height=2.0*cm, kind='proportional')
                    photo_cell = img
                except Exception:
                    photo_cell = Paragraph('—', h_normal)
            else:
                photo_cell = Paragraph('<font color="#9ca3af" size="8">(pas de photo)</font>', h_normal)
            title = Paragraph(f'<font size="9"><b>{_xml_esc_s(item.get("libelle",""))}</b></font>', h_normal)
            checks_table = Table([
                [_make_check_cell('Absent', absent)],
                [_make_check_cell('Présent', present)],
                [_make_check_cell('Conforme', conforme)],
                [_make_check_cell('Non conforme', non_conforme)],
            ], colWidths=[3.5*cm])
            checks_table.setStyle(TableStyle([
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 4),
                ('RIGHTPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 1),
                ('BOTTOMPADDING', (0,0), (-1,-1), 1),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            inner = Table([
                [title, ''],
                [photo_cell, checks_table],
            ], colWidths=[3.5*cm, 4.5*cm])
            inner.setStyle(TableStyle([
                ('SPAN', (0,0), (1,0)),
                ('BACKGROUND', (0,0), (1,0), LIGHT),
                ('ALIGN', (0,0), (1,0), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ALIGN', (0,1), (0,1), 'CENTER'),
                ('LEFTPADDING', (0,0), (-1,-1), 4),
                ('RIGHTPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('BOX', (0,0), (-1,-1), 0.5, BORDER),
                ('LINEBELOW', (0,0), (1,0), 0.5, BORDER),
            ]))
            return inner

        # Disposer 2 cartes par ligne
        sec_rows = []
        row_buf = []
        for it in securite_items:
            row_buf.append(_build_sec_card(it))
            if len(row_buf) == 2:
                sec_rows.append(row_buf)
                row_buf = []
        if row_buf:
            row_buf.append('')
            sec_rows.append(row_buf)
        if sec_rows:
            sec_outer = Table(sec_rows, colWidths=[8.5*cm, 8.5*cm], hAlign='CENTER')
            sec_outer.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 0),
                ('RIGHTPADDING', (0,0), (-1,-1), 0),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(_section_title("CONTRÔLE DES ÉQUIPEMENTS DE SÉCURITÉ", styles))
            story.append(sec_outer)
            story.append(Spacer(1, 6))

    # ═════════ SIGNATURES ═════════
    # v218.214 : pas de signatures sur les BP MAINTENANCE
    if not _is_bp_maintenance:
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
    cards_table = Table(cells, colWidths=[5.5*cm]*3, hAlign='CENTER')
    cards_table.setStyle(TableStyle([
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(_section_title("VUE D'ENSEMBLE", styles))
    story.append(cards_table)
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
        t = Table(rows_t, colWidths=[8*cm, 4*cm, 4.5*cm])
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
        tm = Table(rows_m, colWidths=[4*cm, 4*cm, 4*cm, 4.5*cm])
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
        story.append(_section_title("COMPLÉTION DES GAMMES DE MAINTENANCE PRÉVENTIVE", styles))
        rows_c = [['Bon', 'Équipement', 'Date', 'Opérations', '%']]
        for c in completion_bp:
            rows_c.append([
                Paragraph(esc(c["numero"]), h_normal),
                Paragraph(esc(c["equipement"]), h_normal),
                Paragraph(esc(c["date"]), h_normal),
                Paragraph(f'{c["nb_done"]} / {c["nb_ops"]}', h_normal),
                Paragraph(f'<b>{c["pct"]}%</b>', h_normal),
            ])
        tc = Table(rows_c, colWidths=[2.5*cm, 6*cm, 2.5*cm, 2.5*cm, 2.5*cm])
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
        story.append(tc)
        story.append(Spacer(1, 10))

    # ─── ÉQUIPEMENTS CONCERNÉS ───
    equipements = data.get("equipements") or []
    if equipements:
        story.append(PageBreak())
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
            iv_table = Table(iv_rows, colWidths=[2.5*cm, 3*cm, 3*cm, 3*cm, 1.5*cm])
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
        story.append(PageBreak())
        story.append(_section_title("LISTE COMPLÈTE DES INTERVENTIONS", styles))
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
        ti = Table(rows_i, colWidths=[2*cm, 1.8*cm, 5*cm, 2*cm, 2.5*cm, 1.2*cm, 1.5*cm])
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
        story.append(ti)

    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    buf.seek(0)
    return buf.read()


# ════════════════════════════════════════════════════════════════════════
# PLANNING CLIENT — PDF élégant à transmettre au client
# (v218.131)
# ════════════════════════════════════════════════════════════════════════

def _draw_planning_header_footer(canvas, doc):
    """En-tête et pied de page personnalisés pour le planning client.
    v218.134 : utilise doc.pagesize pour gérer paysage ET portrait."""
    canvas.saveState()
    W, H = doc.pagesize  # v218.134 : adapte automatiquement aux dimensions réelles
    # Bandeau bleu en haut sur toute la largeur
    canvas.setFillColor(ACCENT)
    canvas.rect(0, H - 2.2*cm, W, 2.2*cm, fill=1, stroke=0)
    # Logo SOCOM dans le bandeau
    logo_path = _pick_logo()
    if logo_path:
        try:
            canvas.drawImage(
                logo_path,
                1.2*cm, H - 1.95*cm,
                width=4.5*cm, height=1.4*cm,
                preserveAspectRatio=True, mask='auto'
            )
        except Exception:
            pass
    # Texte titre dans le bandeau (à droite)
    header_info = getattr(doc, '_header_info', None) or {}
    titre = header_info.get('titre', 'Planning de maintenance')
    canvas.setFillColor(colors.white)
    canvas.setFont('Helvetica-Bold', 16)
    canvas.drawRightString(W - 1.2*cm, H - 1.4*cm, titre)
    sous_titre = header_info.get('sous_titre', '')
    if sous_titre:
        canvas.setFont('Helvetica', 9)
        canvas.drawRightString(W - 1.2*cm, H - 1.85*cm, sous_titre)
    # Pied de page : trait fin + n° page + adresse société
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(1.5*cm, 1.4*cm, W - 1.5*cm, 1.4*cm)
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(1.5*cm, 0.9*cm, header_info.get('footer_left', 'SOCOM S.A. — 10 rue du Commerce — L-3895 FOETZ'))
    canvas.drawCentredString(W/2, 0.9*cm, header_info.get('footer_center', ''))
    canvas.drawRightString(W - 1.5*cm, 0.9*cm, f"Page {doc.page}")
    canvas.restoreState()


def _xml_escape_plan(s):
    """Escape les caractères XML pour reportlab Paragraph."""
    if s is None:
        return ''
    return (str(s)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def generate_planning_client_pdf(data):
    """Génère un PDF de planning client à partir des interventions planifiées.
    v218.134 : format paysage, nouvelles colonnes (Équipement, Technique, Localisation, Type, Occurrence, Date)."""
    import io
    from datetime import datetime as _dt
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=landscape(A4),  # v218.134 : format paysage
        leftMargin=1.3*cm, rightMargin=1.3*cm,
        topMargin=2.8*cm, bottomMargin=1.8*cm,
        title="Planning de maintenance"
    )

    projet = data.get('projet') or {}
    annee = data.get('annee') or _dt.now().year
    lignes = data.get('lignes') or []
    date_emission = data.get('date_emission') or _dt.now().strftime('%Y-%m-%d')

    # En-tête personnalisé
    doc._header_info = {
        'titre': f"Planning de maintenance {annee}",
        'sous_titre': projet.get('client_nom') or '',
        'footer_center': f"Émis le {date_emission.split('-')[2]}/{date_emission.split('-')[1]}/{date_emission.split('-')[0]}" if date_emission and '-' in date_emission else '',
    }

    styles = getSampleStyleSheet()
    style_h2 = ParagraphStyle(
        'PlanH2', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=11, textColor=ACCENT,
        spaceAfter=6, spaceBefore=10
    )
    style_normal = ParagraphStyle(
        'PlanNormal', parent=styles['Normal'],
        fontName='Helvetica', fontSize=10, textColor=TEXT, leading=13
    )
    style_cell = ParagraphStyle(
        'PlanCell', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9, textColor=TEXT, leading=12
    )
    style_muted = ParagraphStyle(
        'PlanMuted', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9, textColor=MUTED, leading=12
    )

    story = []

    # v218.135 : Titre projet (au lieu du tableau d'introduction)
    titre_projet = projet.get('nom') or ''
    num_projet = projet.get('numero_projet') or ''
    if titre_projet or num_projet:
        style_titre_projet = ParagraphStyle(
            'TitreProjet', parent=styles['Heading1'],
            fontName='Helvetica-Bold', fontSize=16, textColor=ACCENT,
            spaceAfter=4, spaceBefore=0, alignment=0
        )
        style_num_projet = ParagraphStyle(
            'NumProjet', parent=styles['Normal'],
            fontName='Helvetica', fontSize=12, textColor=MUTED,
            spaceAfter=12, spaceBefore=0, alignment=0
        )
        if titre_projet:
            story.append(Paragraph(_xml_escape_plan(titre_projet), style_titre_projet))
        if num_projet:
            story.append(Paragraph("N° projet : " + _xml_escape_plan(num_projet), style_num_projet))
        story.append(Spacer(1, 0.3*cm))

    # ─── Tableau principal ──────────────────────────
    # v218.135 : titre "Calendrier des interventions" retiré (titre projet remplace l'intro)

    # v218.134 : Nouvelles colonnes : N°, Équipement, Technique, Localisation, Type, Occurrence, Date
    rows_table = [['N°', 'Équipement', 'Technique', 'Localisation', 'Type', 'Occurrence', 'Date prévue']]

    lignes_valides = [l for l in lignes if l.get('date')]
    def _date_key(l):
        try:
            return _dt.strptime(l['date'], '%Y-%m-%d')
        except Exception:
            return _dt.max
    lignes_valides.sort(key=_date_key)

    JOURS_NOMS = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi', 'Dimanche']
    MOIS_NOMS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin',
                 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre']

    for idx, l in enumerate(lignes_valides, 1):
        try:
            d = _dt.strptime(l['date'], '%Y-%m-%d')
            date_fmt = f"{JOURS_NOMS[d.weekday()]} {d.day} {MOIS_NOMS[d.month-1]} {d.year}"
        except Exception:
            date_fmt = l.get('date', '—')

        # Type d'intervention (ex: "Entretien", "Visite") — déjà extrait côté frontend
        type_iv = l.get('type_intervention') or l.get('gamme') or '—'
        if l.get('occ_total', 1) > 1:
            type_iv += f" ({l.get('occ_idx', 0) + 1}/{l['occ_total']})"
        # Occurrence (périodicité)
        occurrence = l.get('periodicite') or '—'

        rows_table.append([
            str(idx),
            Paragraph(f"<b>{_xml_escape_plan(l.get('equipement', '—'))}</b>", style_cell),
            Paragraph(_xml_escape_plan(l.get('technique', '') or '—'), style_cell),
            Paragraph(_xml_escape_plan(l.get('localisation', '') or '—'), style_cell),
            Paragraph(_xml_escape_plan(type_iv), style_cell),
            Paragraph(_xml_escape_plan(occurrence), style_cell),
            date_fmt,
        ])

    if len(rows_table) == 1:
        story.append(Paragraph("<i>Aucune intervention planifiée pour cette période.</i>", style_muted))
    else:
        # v218.138 : largeurs de colonnes calculées dynamiquement selon la longueur max du contenu
        # → aucun retour à la ligne forcé (le contenu détermine la largeur)
        # Largeur utile A4 paysage avec marges 1.3+1.3 = 29.7 - 2.6 = 27.1 cm

        # Mesurer la longueur (en caractères) du contenu max de chaque colonne
        # On reconstruit en texte brut pour la mesure
        def _text_len(item):
            """Retourne la longueur textuelle d'une cellule (str ou Paragraph)."""
            if hasattr(item, 'text'):
                # Paragraph : approximer en retirant les balises HTML
                t = item.text or ''
                import re as _re
                t = _re.sub(r'<[^>]+>', '', t)
                return len(t)
            return len(str(item))

        # Largeurs en caractères (max sur toutes les lignes y compris en-tête)
        ncol = len(rows_table[0])
        char_widths = [0] * ncol
        for row in rows_table:
            for i, cell in enumerate(row):
                char_widths[i] = max(char_widths[i], _text_len(cell))

        # Conversion caractères → cm. Helvetica 9pt ≈ 0.18 cm/caractère pour caractères moyens.
        # On garde un peu de padding (2 cm de padding/marges internes ~ 0.3 cm par cellule)
        CHAR_TO_CM = 0.17
        PAD_PER_COL = 0.6  # padding gauche + droite
        # Min/max pour éviter les colonnes trop étroites ou trop larges
        # Colonnes: 0=N°, 1=Équipement, 2=Technique, 3=Localisation, 4=Type, 5=Occurrence, 6=Date
        MIN_CM = [0.8, 2.5, 2.0, 2.0, 2.0, 2.0, 4.0]
        MAX_CM = [1.5, 8.0, 4.5, 6.5, 6.5, 4.0, 6.0]

        raw_widths = []
        for i in range(ncol):
            w = char_widths[i] * CHAR_TO_CM + PAD_PER_COL
            w = max(MIN_CM[i], min(MAX_CM[i], w))
            raw_widths.append(w)

        # Ajuster pour que la somme = 27.1 cm (étirer ou contracter proportionnellement)
        total_w = sum(raw_widths)
        target_w = 27.1
        if total_w > 0:
            scale = target_w / total_w
            final_widths = [w * scale for w in raw_widths]
        else:
            final_widths = raw_widths

        main_table = Table(
            rows_table,
            colWidths=[w*cm for w in final_widths],
            repeatRows=1
        )
        main_table.setStyle(TableStyle([
            # En-tête
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            # Corps
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT),
            ('VALIGN', (0, 1), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),   # N°
            ('ALIGN', (6, 1), (6, -1), 'LEFT'),     # Date
            ('TOPPADDING', (0, 1), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 7),
            ('LEFTPADDING', (0, 1), (-1, -1), 6),
            ('RIGHTPADDING', (0, 1), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT]),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
            ('LINEBELOW', (0, 0), (-1, 0), 1.5, ACCENT),
        ]))
        story.append(main_table)

    story.append(Spacer(1, 0.6*cm))

    # v218.134 : Note simplifiée
    notes = (
        "<b>Note :</b> Les dates indiquées sont prévisionnelles et peuvent faire l'objet "
        "d'ajustements en concertation avec le client."
    )
    story.append(Paragraph(notes, style_muted))

    # v218.134 : Bloc signature retiré

    doc.build(story, onFirstPage=_draw_planning_header_footer, onLaterPages=_draw_planning_header_footer)
    buf.seek(0)
    return buf.read()
