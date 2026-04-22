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
    """Titre de section stylé (bandeau bleu clair)."""
    return Paragraph(
        f'<font color="#1E3A8A"><b>{text}</b></font>',
        ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading3'],
            fontSize=11,
            textColor=ACCENT,
            spaceAfter=6,
            spaceBefore=4,
            backColor=LIGHT,
            borderPadding=6,
            leftIndent=0,
            leading=14,
        )
    )


def _info_row(label, value, styles):
    """Ligne étiquette/valeur pour bloc 'Informations générales'."""
    return [
        Paragraph(f'<font color="#64748B" size="9"><b>{label}</b></font>', styles['Normal']),
        Paragraph(f'<font color="#0F172A" size="10">{value or "—"}</font>', styles['Normal']),
    ]


def generate_rapport(data):
    """Génère un rapport PDF (bytes). Voir docstring du module pour le schéma data."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=2.5*cm, bottomMargin=1.5*cm,
        title="Rapport d'intervention SOCOM",
        author="SOCOM GMAO",
    )
    styles = getSampleStyleSheet()
    h_normal = ParagraphStyle(
        'HNormal', parent=styles['Normal'],
        fontSize=10, textColor=TEXT, leading=14
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
        ParagraphStyle('Title', fontSize=16, textColor=ACCENT, alignment=1, spaceAfter=10)
    ))

    # ═════════ LOGO SÉCURITÉ (PPSS + EPI) ═════════
    if os.path.exists(LOGO_SECU):
        try:
            img_secu = Image(LOGO_SECU, width=5.4*cm, height=3.6*cm, kind='proportional')
            logos_table = Table([[img_secu]], colWidths=[17*cm])
            logos_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ]))
            story.append(logos_table)
            story.append(Spacer(1, 8))
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
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, LIGHT]),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
    ]))
    story.append(KeepTogether([_section_title("INFORMATIONS GÉNÉRALES", styles), info_table]))
    story.append(Spacer(1, 10))

    # ═════════ ÉQUIPEMENT CONCERNÉ ═════════
    # Construction dynamique : on n'affiche une ligne que si la donnée est renseignée
    eq_rows = [
        _info_row('Désignation', data.get('equipement', '—'), styles),
    ]
    mm_ = (data.get('marque_modele') or '').strip()
    if mm_ and mm_ != '—':
        eq_rows.append(_info_row('Marque / Modèle', mm_, styles))
    if data.get('eq_puissance'):
        eq_rows.append(_info_row('Puissance', data['eq_puissance'], styles))
    if data.get('eq_numero_serie'):
        eq_rows.append(_info_row('N° de série', data['eq_numero_serie'], styles))
    if data.get('eq_in_out'):
        eq_rows.append(_info_row('Intérieur / Extérieur', data['eq_in_out'], styles))
    if data.get('localisation') and data.get('localisation') not in ('—', ''):
        eq_rows.append(_info_row('Localisation', data['localisation'], styles))
    if data.get('technique') and data.get('technique') not in ('—', ''):
        eq_rows.append(_info_row('Technique', data['technique'], styles))
    if data.get('eq_date_mise_service'):
        eq_rows.append(_info_row('Date de mise en service', data['eq_date_mise_service'], styles))
    if data.get('eq_statut'):
        # Traduction du statut pour lisibilité
        _statut_labels = {
            'EN_SERVICE': 'En service',
            'HORS_SERVICE': 'Hors service',
            'EN_PANNE': 'En panne',
            'EN_MAINTENANCE': 'En maintenance',
            'ARCHIVE': 'Archivé',
        }
        st = data['eq_statut']
        eq_rows.append(_info_row('Statut', _statut_labels.get(st, st), styles))
    if data.get('eq_notes'):
        notes = data['eq_notes'].replace('\n', '<br/>')
        eq_rows.append([
            Paragraph('<font color="#64748B" size="9"><b>Notes</b></font>', styles['Normal']),
            Paragraph(f'<font color="#0F172A" size="10">{notes}</font>', styles['Normal']),
        ])

    eq_table = Table(eq_rows, colWidths=[5*cm, 12*cm])
    eq_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, LIGHT]),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER),
    ]))
    story.append(KeepTogether([_section_title("ÉQUIPEMENT CONCERNÉ", styles), eq_table]))
    story.append(Spacer(1, 10))

    # ═════════ DESCRIPTIF (saisi à la création du bon) ═════════
    descriptif = (data.get('description') or '').strip()
    if descriptif:
        # Support simple des sauts de ligne
        descriptif_html = descriptif.replace('\n', '<br/>')
        desc_para = Paragraph(descriptif_html, h_normal)
        desc_cell = Table([[desc_para]], colWidths=[17*cm])
        desc_cell.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        label = "DESCRIPTIF DU DÉPANNAGE" if type_label == 'DEPANNAGE' else "DESCRIPTIF DE L'INTERVENTION"
        story.append(KeepTogether([_section_title(label, styles), desc_cell]))
        story.append(Spacer(1, 10))

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
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
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
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
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
                    ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('BOX', (0, 0), (-1, -1), 0.5, BORDER),
                    ('GRID', (0, 0), (-1, -2), 0.3, BORDER),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, LIGHT]),
                    ('BACKGROUND', (0, -1), (-1, -1), LIGHT),
                    ('FONTNAME', (3, -1), (-1, -1), 'Helvetica-Bold'),
                    ('TEXTCOLOR', (3, -1), (-1, -1), ACCENT),
                    ('LINEABOVE', (0, -1), (-1, -1), 1, ACCENT),
                ]))
                cr_block = KeepTogether([cr_header, obs_cell, Spacer(1, 4), iv_table, Spacer(1, 10)])
            else:
                cr_block = KeepTogether([cr_header, obs_cell, Spacer(1, 10)])

            cr_elements.append(cr_block)

        # Titre + 1er CR groupés, puis les autres
        if len(cr_elements) >= 2:
            story.append(KeepTogether(cr_elements[:2]))
            for block in cr_elements[2:]:
                story.append(block)
        else:
            story.extend(cr_elements)

        # ═════════ TOTAL GÉNÉRAL DES HEURES ═════════
        # Affiché en bas de la section, cumule toutes les heures de tous les CRs
        total_rows = [[
            Paragraph(
                f'<font size="11" color="#1E3A8A"><b>TOTAL GÉNÉRAL DE L\'INTERVENTION</b></font>',
                styles['Normal']
            ),
            Paragraph(
                f'<font size="13" color="#1E3A8A"><b>{_format_heures(total_general)}</b></font>',
                ParagraphStyle('tg', parent=styles['Normal'], alignment=2)
            )
        ]]
        total_table = Table(total_rows, colWidths=[11*cm, 6*cm])
        total_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
            ('BOX', (0, 0), (-1, -1), 1.2, ACCENT),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(Spacer(1, 4))
        story.append(total_table)
        story.append(Spacer(1, 14))

    # ═════════ SIGNATURES ═════════
    sig_lbl_style = ParagraphStyle(
        'SigLbl', fontSize=9, textColor=ACCENT,
        fontName='Helvetica-Bold', alignment=1
    )
    sig_data = [
        [Paragraph('Pour le client', sig_lbl_style),
         '',
         Paragraph('Pour SOCOM', sig_lbl_style)],
        [' ', '', ' '],
        [' ', '', ' '],
        [Paragraph('<font size="7" color="#64748B">Nom, fonction, signature</font>',
                   ParagraphStyle('sfn', fontSize=7, alignment=1)),
         '',
         Paragraph('<font size="7" color="#64748B">Nom, fonction, signature</font>',
                   ParagraphStyle('sfn', fontSize=7, alignment=1))],
    ]
    sig_table = Table(sig_data, colWidths=[7.5*cm, 2*cm, 7.5*cm], rowHeights=[0.8*cm, 1.2*cm, 1.2*cm, 0.6*cm])
    sig_table.setStyle(TableStyle([
        ('BOX', (0, 0), (0, -1), 0.5, BORDER),
        ('BOX', (2, 0), (2, -1), 0.5, BORDER),
        ('BACKGROUND', (0, 0), (0, 0), LIGHT),
        ('BACKGROUND', (2, 0), (2, 0), LIGHT),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(KeepTogether([_section_title("SIGNATURES", styles), sig_table]))

    # Build
    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    buf.seek(0)
    return buf.read()
