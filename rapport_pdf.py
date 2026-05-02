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
        tbl = Table([[para]], colWidths=[width])
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
    technique_nom = (data.get('technique') or '').strip()
    # Mode maintenance : nouvelle mise en page avec logo projet centré + page break
    is_maintenance_layout = (type_label == 'MAINTENANCE')
    # Espace entre les sections (doublé en maintenance pour aérer la page 2)
    _sect_gap = 12 if is_maintenance_layout else 6

    if is_maintenance_layout:
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
            ParagraphStyle('Title', fontSize=28, textColor=ACCENT, alignment=1,
                           spaceAfter=8, leading=34)
        ))
        # Sous-titre : nom de la technique (16pt)
        sous_titre_txt = ""
        if technique_nom and technique_nom not in ('—', ''):
            sous_titre_txt = technique_nom.upper()
        if sous_titre_txt:
            story.append(Paragraph(
                f"<b>{sous_titre_txt}</b>",
                ParagraphStyle('Subtitle', fontSize=16, textColor=ACCENT, alignment=1,
                               spaceAfter=4, leading=20)
            ))
        # Espace libre sous le nom de la technique
        story.append(Spacer(1, 1.2*cm))
    else:
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
        # Logo projet centré (si fourni dans les data)
        projet_logo_path = (data.get('projet_logo_path') or '').strip()
        if projet_logo_path and os.path.exists(projet_logo_path):
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
        gamme_ops_list_main = data.get('gamme_operations') or []
        has_gamme_ops_main = any(g.get('operations') for g in gamme_ops_list_main)
        if has_gamme_ops_main:
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
        cr_list = data.get('comptes_rendus') or []
        if cr_list:
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
            story.append(Spacer(1, _sect_gap))

    # ═════════ CELLULES (Haute tension uniquement) ═════════
    cellules = data.get('cellules') or []
    if cellules:
        cell_rows = []
        for idx, c in enumerate(cellules, start=1):
            # Titre de la cellule (ligne pleine bleu clair sur 4 colonnes)
            cell_rows.append([
                Paragraph(f'<font color="#1E3A8A"><b>Cellule {idx}</b></font>', h_normal),
                '', '', ''
            ])
            # Lignes label/valeur en 2 colonnes (4 cellules par ligne)
            pairs = [
                ('Désignation', c.get('designation','') or ''),
                ('Marque', c.get('marque','') or ''),
                ('Type', c.get('type','') or ''),
            ]
            # Ne garder que les valeurs renseignées
            pairs = [(k, v) for k, v in pairs if str(v).strip()]
            for n in range(0, len(pairs), 2):
                left_lbl, left_val = pairs[n]
                right_lbl, right_val = pairs[n+1] if n+1 < len(pairs) else ('', '')
                cell_rows.append([
                    Paragraph(f'<b>{left_lbl}</b>', h_normal), Paragraph(str(left_val), h_normal),
                    Paragraph(f'<b>{right_lbl}</b>', h_normal) if right_lbl else '',
                    Paragraph(str(right_val), h_normal) if right_val else ''
                ])
        if cell_rows:
            cell_table = Table(cell_rows, colWidths=[3.5*cm, 5*cm, 3.5*cm, 5*cm])
            cell_style = [
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
            # Pour chaque ligne "Cellule N" : fusionner les 4 cellules + fond bleu clair sur toute la ligne
            for row_idx, row in enumerate(cell_rows):
                if row[1] == '' and row[2] == '' and row[3] == '':
                    cell_style.append(('SPAN', (0, row_idx), (-1, row_idx)))
                    cell_style.append(('BACKGROUND', (0, row_idx), (-1, row_idx), LIGHT))
            cell_table.setStyle(TableStyle(cell_style))
            story.append(KeepTogether([_section_title("CELLULES", styles), cell_table]))
            story.append(Spacer(1, _sect_gap))

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
        # Pour 'graphique', 'preconisations' et 'mesures_batteries', les lignes ne sont pas affichées une à une
        if not lignes and bloc_type not in ('graphique', 'preconisations', 'mesures_batteries'):
            continue

        # ─── Type TABLEAU : 2 colonnes (Élément | Valeur) avec rendu adapté par type de champ ───
        if bloc_type == 'tableau':
            import json as _json
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
                    parts = (val_raw or '').split('|||', 1)
                    p1 = parts[0].strip() if len(parts) >= 1 else ''
                    p2 = parts[1].strip() if len(parts) >= 2 else ''
                    if p1 and p2:
                        display = _xml_esc_m(p1) + ' <font color="#94a3b8">/</font> ' + _xml_esc_m(p2)
                    elif p1:
                        display = _xml_esc_m(p1)
                    elif p2:
                        display = _xml_esc_m(p2)
                    else:
                        display = '—'
                    mes_data.append([_mod_label(lg.get("libelle","")), _mod_val_html(display)])

                else:  # text_short
                    display = _xml_esc_m(val_raw) if val_raw else '—'
                    mes_data.append([_mod_label(lg.get("libelle","")), _mod_val_html(display)])

            mes_table = Table(mes_data, colWidths=[_avail_w * 0.8, _avail_w * 0.2])
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
                # Format date helper
                def _fmt_date_p(s):
                    if not s: return '—'
                    try:
                        return datetime.strptime(s, "%Y-%m-%d").strftime("%d/%m/%Y")
                    except Exception:
                        return str(s)
                # Header
                hdr_style = ParagraphStyle('precoHdr', fontSize=8, textColor=colors.HexColor('#64748B'), fontName='Helvetica-Bold', leading=10)
                cell_style = ParagraphStyle('precoCell', fontSize=8, textColor=colors.HexColor('#0f172a'), leading=10)
                preco_data = [[
                    Paragraph('Type', hdr_style),
                    Paragraph('Référence', hdr_style),
                    Paragraph('N° série', hdr_style),
                    Paragraph('Installation', hdr_style),
                    Paragraph('Fin de vie', hdr_style),
                    Paragraph('Statut', hdr_style),
                    Paragraph('Préconisation', hdr_style),
                ]]
                row_styles_p = []
                STATUT_COLORS = {
                    'OK': ('#10B981', '#ECFDF5'),
                    'A_SURVEILLER': ('#F59E0B', '#FEF3C7'),
                    'A_REMPLACER': ('#DC2626', '#FEE2E2'),
                }
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
                    statut = (pc.get('statut') or 'OK').upper()
                    statut_label = {'OK':'OK','A_SURVEILLER':'À surveiller','A_REMPLACER':'À remplacer'}.get(statut, statut)
                    statut_col_text, statut_col_bg = STATUT_COLORS.get(statut, ('#64748b','#F1F5F9'))
                    level = (pc.get('preconisation_level') or 'ok')
                    prec_col_text, prec_col_bg = LEVEL_COLORS.get(level, ('#64748b','#F1F5F9'))
                    statut_html = f'<font color="{statut_col_text}"><b>{_xml_esc_p(statut_label)}</b></font>'
                    preco_html  = f'<font color="{prec_col_text}">{_xml_esc_p(pc.get("preconisation",""))}</font>'
                    preco_data.append([
                        Paragraph(_xml_esc_p(pc.get('type_piece','')), cell_style),
                        Paragraph(_xml_esc_p(pc.get('reference','') or '—'), cell_style),
                        Paragraph(_xml_esc_p(pc.get('numero_serie','') or '—'), cell_style),
                        Paragraph(_fmt_date_p(pc.get('date_installation')), cell_style),
                        Paragraph(_fmt_date_p(pc.get('date_fin_de_vie')), cell_style),
                        Paragraph(statut_html, cell_style),
                        Paragraph(preco_html, cell_style),
                    ])
                    # Coloration de la cellule statut + préconisation
                    row_styles_p.append(('BACKGROUND', (5, row_idx), (5, row_idx), colors.HexColor(statut_col_bg)))
                    row_styles_p.append(('BACKGROUND', (6, row_idx), (6, row_idx), colors.HexColor(prec_col_bg)))
                preco_table = Table(preco_data, colWidths=[
                    _avail_w * 0.129, _avail_w * 0.141, _avail_w * 0.141,
                    _avail_w * 0.118, _avail_w * 0.118, _avail_w * 0.129,
                    _avail_w * 0.224
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
            story.append(Spacer(1, _sect_gap))

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
