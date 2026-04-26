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
import io, os
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
    doc._header_info = {
        'numero_iv': data.get('numero_iv', ''),
        'date': data.get('date', ''),
    }

    story = []

    # ═════════ TITRE ═════════
    type_label = (data.get('type_label') or '').upper()
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
    if os.path.exists(LOGO_SECU):
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

    # ═════════ DESCRIPTIF (saisi à la création du bon) ═════════
    descriptif = (data.get('description') or '').strip()
    is_maint = data.get('is_maintenance')
    gamme_ops_list = data.get('gamme_operations') or []
    has_gamme_ops = is_maint and any(g.get('operations') for g in gamme_ops_list)

    if has_gamme_ops:
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
        story.append(Spacer(1, 6))

    # ═════════ COMPTES-RENDUS D'INTERVENTION ═════════
    crs = data.get('comptes_rendus') or []
    if crs:
        cr_elements = [_section_title("COMPTES-RENDUS D'INTERVENTION", styles)]
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

    # ═════════ SIGNATURES ═════════
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
