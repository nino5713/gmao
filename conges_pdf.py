"""
Générateur de PDF pour les demandes de congés (formulaire SOCOM).

Reproduit fidèlement le formulaire interne SOCOM (Demande_de_congé_*.docx) :
- En-tête : "Formulaire" + date + numéro de version + bandeau "DEMANDE DE CONGES"
- Date de la demande
- Nom + Prénom du technicien
- Matricule
- Période (du / au) + nombre de jours
- Motif (Congé légal ☒ / Congé extraordinaire ☐)
- Signature du demandeur
- Tableau d'avis (Responsable + Directeur de service) avec accord/refus/nom/signature/date
- Mention "Copie à transmettre au service des ressources humaines"
- Recommandations légales (Code du travail luxembourgeois + contrat collectif)

Utilisation :
    from conges_pdf import generate_demande_conge_pdf
    pdf_bytes = generate_demande_conge_pdf({
        "nom_complet": "SALMON David",        # ou nom seul - sera split
        "matricule": "2507",
        "date_demande": "16/03/2026",         # date création de la demande
        "date_debut": "05/06/2026",
        "date_fin": "05/06/2026",
        "nb_jours": "1 jour" ou "0,5 jour",
        "motif": "LEGAL" ou "EXTRAORDINAIRE",
        "commentaire": "...",                 # optionnel
        "responsable_nom": "SALMON Nicolas",   # le manager
        "responsable_decision": "ACCORD",     # ACCORD / REFUS / "" (en attente)
        "responsable_date": "17/03/2026",      # date décision
        "directeur_nom": "",                  # optionnel (souvent vide)
        "directeur_decision": "",
        "directeur_date": "",
    })
"""
import io, os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ──────────────────────────────────────────────────────────────
# Palette SOCOM (cohérente avec rapport_pdf.py)
# ──────────────────────────────────────────────────────────────
ACCENT = colors.HexColor('#1E3A8A')   # bleu principal
LIGHT  = colors.HexColor('#EFF6FF')   # bleu très clair (fond)
BORDER = colors.HexColor('#CBD5E1')   # gris bordures
TEXT   = colors.HexColor('#0F172A')   # texte principal
MUTED  = colors.HexColor('#64748B')   # texte secondaire

# Chemins des logos (à côté du fichier Python)
HERE = os.path.dirname(os.path.abspath(__file__))
LOGO_SOCOM_MENU = os.path.join(HERE, 'socom_menu_logo.png')
LOGO_SOCOM_ALT  = os.path.join(HERE, 'socom_logo.png')


def _pick_logo():
    """Choisit le premier logo SOCOM disponible."""
    for p in (LOGO_SOCOM_MENU, LOGO_SOCOM_ALT):
        if os.path.exists(p):
            return p
    return None


def _split_nom_prenom(nom_complet):
    """Découpe un nom complet en NOM et Prénom.
    Convention SOCOM observée : 'SALMON David' (NOM en MAJ + Prénom).
    Si plusieurs mots en MAJ, on considère qu'ils font partie du nom.
    """
    if not nom_complet:
        return "", ""
    parts = nom_complet.strip().split()
    nom_parts = []
    prenom_parts = []
    for p in parts:
        # Si c'est tout en majuscules → fait partie du nom
        if p == p.upper() and any(c.isalpha() for c in p):
            nom_parts.append(p)
        else:
            prenom_parts.append(p)
    if not nom_parts:
        # Fallback : 1er mot = nom, reste = prénom
        return parts[0], " ".join(parts[1:]) if len(parts) > 1 else ""
    if not prenom_parts:
        return " ".join(nom_parts), ""
    return " ".join(nom_parts), " ".join(prenom_parts)


def _checkbox(checked):
    """Renvoie une représentation HTML de case à cocher.
    Utilise des entités/caractères supportés par Helvetica.
    """
    if checked:
        # Carré vide avec un X dedans (compatible toutes polices)
        return "<font color='#1E3A8A'><b>[X]</b></font>"
    else:
        return "<font color='#94A3B8'>[&nbsp;&nbsp;]</font>"


def generate_demande_conge_pdf(data):
    """Génère le PDF du formulaire SOCOM de demande de congés.

    Args:
        data (dict) : voir docstring du module
    Returns:
        bytes : contenu du PDF
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title="Demande de congés SOCOM"
    )

    styles = getSampleStyleSheet()
    style_normal = ParagraphStyle(
        'normal', parent=styles['Normal'],
        fontName='Helvetica', fontSize=10, textColor=TEXT, leading=13
    )
    style_label = ParagraphStyle(
        'label', parent=style_normal,
        fontName='Helvetica-Bold'
    )
    style_h1 = ParagraphStyle(
        'h1', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=16, textColor=ACCENT,
        alignment=TA_CENTER, spaceAfter=8, spaceBefore=4
    )
    style_recommand = ParagraphStyle(
        'recommand', parent=style_normal,
        fontSize=8.5, textColor=MUTED, leading=11
    )
    style_recommand_bold = ParagraphStyle(
        'recommand_bold', parent=style_recommand,
        fontName='Helvetica-Bold'
    )
    style_footer = ParagraphStyle(
        'footer', parent=style_normal,
        fontSize=8, textColor=MUTED, alignment=TA_CENTER
    )

    elements = []

    # ──────────────────────────────────────────────────────────
    # EN-TÊTE : Logo + bandeau "Formulaire" + date version
    # ──────────────────────────────────────────────────────────
    logo_path = _pick_logo()
    if logo_path:
        try:
            logo = Image(logo_path, width=3.5*cm, height=1.2*cm, kind='proportional')
        except Exception:
            logo = Paragraph("<b>SOCOM</b>", style_label)
    else:
        logo = Paragraph("<b>SOCOM</b>", style_label)

    header_table = Table(
        [[
            logo,
            Paragraph("<b>Formulaire</b>", ParagraphStyle('hdr', parent=style_normal, alignment=TA_CENTER, fontSize=11)),
            Paragraph("25/01/2018", ParagraphStyle('hdr2', parent=style_normal, alignment=TA_CENTER, fontSize=10, textColor=MUTED))
        ]],
        colWidths=[5*cm, 6*cm, 6*cm], rowHeights=[1.4*cm]
    )
    header_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (0, 0), 'CENTER'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(header_table)

    # Titre principal "DEMANDE DE CONGES"
    title_table = Table(
        [[Paragraph("<b>DEMANDE DE CONGÉS</b>",
            ParagraphStyle('title', parent=style_normal, alignment=TA_CENTER,
                           fontSize=14, textColor=colors.white, fontName='Helvetica-Bold'))]],
        colWidths=[17*cm], rowHeights=[0.9*cm]
    )
    title_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), ACCENT),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(title_table)
    elements.append(Spacer(1, 0.6*cm))

    # ──────────────────────────────────────────────────────────
    # Date de la demande
    # ──────────────────────────────────────────────────────────
    date_demande = data.get('date_demande', '')
    elements.append(Paragraph(
        f"<b>Date :</b>&nbsp;&nbsp;&nbsp;{date_demande}",
        style_normal
    ))
    elements.append(Spacer(1, 0.4*cm))

    # ──────────────────────────────────────────────────────────
    # Nom / Prénom
    # ──────────────────────────────────────────────────────────
    nom_complet = data.get('nom_complet', '')
    nom, prenom = _split_nom_prenom(nom_complet)
    nom_prenom_table = Table(
        [[
            Paragraph(f"<b>Nom :</b>&nbsp;&nbsp;{nom}", style_normal),
            Paragraph(f"<b>Prénom :</b>&nbsp;&nbsp;{prenom}", style_normal),
        ]],
        colWidths=[8.5*cm, 8.5*cm], rowHeights=[0.8*cm]
    )
    nom_prenom_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(nom_prenom_table)

    # Matricule
    matricule_table = Table(
        [[Paragraph(f"<b>Matricule :</b>&nbsp;&nbsp;{data.get('matricule','')}", style_normal)]],
        colWidths=[17*cm], rowHeights=[0.8*cm]
    )
    matricule_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(matricule_table)
    elements.append(Spacer(1, 0.4*cm))

    # ──────────────────────────────────────────────────────────
    # Compteur "Congés pris depuis le 1er janvier" — laissé vide
    # (pas géré dans la GMAO selon la décision projet)
    # ──────────────────────────────────────────────────────────
    compteur_table = Table(
        [[
            Paragraph("<b>Congés pris depuis le 1<sup>er</sup> Janvier</b>", style_normal),
            Paragraph("<b>Nombre de jours :</b>", style_normal),
            Paragraph("&nbsp;", style_normal),  # case vide à remplir manuellement
        ]],
        colWidths=[8.5*cm, 4*cm, 4.5*cm], rowHeights=[0.8*cm]
    )
    compteur_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(compteur_table)
    elements.append(Spacer(1, 0.5*cm))

    # ──────────────────────────────────────────────────────────
    # Phrase période
    # ──────────────────────────────────────────────────────────
    nb_jours = data.get('nb_jours', '')
    period_text = (f"Demande de congés du <b>{data.get('date_debut','')}</b> inclus "
                   f"au <b>{data.get('date_fin','')}</b> inclus, soit <b>{nb_jours}</b>")
    elements.append(Paragraph(period_text, style_normal))
    elements.append(Spacer(1, 0.5*cm))

    # ──────────────────────────────────────────────────────────
    # Motif (cases à cocher)
    # ──────────────────────────────────────────────────────────
    motif = data.get('motif', 'LEGAL')
    is_legal = (motif == 'LEGAL')
    is_extra = (motif == 'EXTRAORDINAIRE')

    motif_table = Table(
        [
            [
                Paragraph("<b>MOTIF :</b>", style_normal),
                Paragraph(f"Congé légal {_checkbox(is_legal)}", style_normal),
                Paragraph("", style_normal),
            ],
            [
                Paragraph("", style_normal),
                Paragraph(f"Congé extraordinaire {_checkbox(is_extra)}", style_normal),
                Paragraph("<i>Motif : Joindre un justificatif.</i>", style_normal),
            ],
        ],
        colWidths=[3*cm, 6*cm, 8*cm], rowHeights=[0.7*cm, 0.7*cm]
    )
    motif_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('SPAN', (0, 0), (0, 1)),  # MOTIF fusionné sur 2 lignes
    ]))
    elements.append(motif_table)
    elements.append(Spacer(1, 0.4*cm))

    # Commentaire (si fourni) — pas dans le formulaire d'origine mais utile
    if data.get('commentaire'):
        elements.append(Paragraph(
            f"<b>Commentaire :</b> <i>{data['commentaire']}</i>",
            style_normal
        ))
        elements.append(Spacer(1, 0.3*cm))

    # ──────────────────────────────────────────────────────────
    # Mention de réserve
    # ──────────────────────────────────────────────────────────
    elements.append(Paragraph(
        "<i>Un accord de congés peut être annulé par la Direction en cas d'évènements imprévisibles.</i>",
        ParagraphStyle('reserve', parent=style_normal, fontSize=9, textColor=MUTED)
    ))
    elements.append(Spacer(1, 0.4*cm))

    # Signature du demandeur
    elements.append(Paragraph("<b>Signature du demandeur :</b>", style_normal))
    elements.append(Spacer(1, 1.2*cm))  # Espace pour signature manuscrite

    # ──────────────────────────────────────────────────────────
    # Tableau des avis (Responsable + Directeur)
    # ──────────────────────────────────────────────────────────
    resp_decision = (data.get('responsable_decision') or '').upper()
    resp_accord = (resp_decision == 'ACCORD')
    resp_refus = (resp_decision == 'REFUS')
    dir_decision = (data.get('directeur_decision') or '').upper()
    dir_accord = (dir_decision == 'ACCORD')
    dir_refus = (dir_decision == 'REFUS')

    avis_data = [
        # En-tête
        [
            Paragraph("", style_normal),
            Paragraph("<b>Accord</b>", ParagraphStyle('hdr', parent=style_normal, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Refus</b>", ParagraphStyle('hdr', parent=style_normal, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Nom</b>", ParagraphStyle('hdr', parent=style_normal, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Signature</b>", ParagraphStyle('hdr', parent=style_normal, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Date</b>", ParagraphStyle('hdr', parent=style_normal, alignment=TA_CENTER, fontName='Helvetica-Bold')),
        ],
        # Avis du Responsable
        [
            Paragraph("<b>Avis du Responsable</b>", style_normal),
            Paragraph(_checkbox(resp_accord), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER, fontSize=11)),
            Paragraph(_checkbox(resp_refus), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER, fontSize=11)),
            Paragraph(data.get('responsable_nom', ''), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER)),
            Paragraph("", style_normal),  # signature manuscrite
            Paragraph(data.get('responsable_date', ''), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER)),
        ],
        # Avis du Directeur du service
        [
            Paragraph("<b>Avis du Directeur du service</b>", style_normal),
            Paragraph(_checkbox(dir_accord), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER, fontSize=11)),
            Paragraph(_checkbox(dir_refus), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER, fontSize=11)),
            Paragraph(data.get('directeur_nom', ''), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER)),
            Paragraph("", style_normal),
            Paragraph(data.get('directeur_date', ''), ParagraphStyle('cell', parent=style_normal, alignment=TA_CENTER)),
        ],
        # Mention RH
        [
            Paragraph(
                "<i>Copie à transmettre au service des ressources humaines</i>",
                ParagraphStyle('rh', parent=style_normal, alignment=TA_CENTER, fontSize=9, textColor=MUTED)
            ),
        ],
    ]

    avis_table = Table(
        avis_data,
        colWidths=[5*cm, 1.7*cm, 1.7*cm, 3.6*cm, 2.5*cm, 2.5*cm],
        rowHeights=[0.7*cm, 1.2*cm, 1.2*cm, 0.6*cm]
    )
    avis_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, 2), 0.5, BORDER),
        ('BOX', (0, 3), (-1, 3), 0.5, BORDER),
        ('SPAN', (0, 3), (-1, 3)),  # ligne RH fusionnée
        ('BACKGROUND', (0, 0), (-1, 0), LIGHT),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(avis_table)
    elements.append(Spacer(1, 0.6*cm))

    # ──────────────────────────────────────────────────────────
    # Recommandations légales
    # ──────────────────────────────────────────────────────────
    elements.append(Paragraph("<b>Recommandations :</b>", style_recommand_bold))
    elements.append(Spacer(1, 0.15*cm))
    elements.append(Paragraph("Se référer :", style_recommand))
    elements.append(Spacer(1, 0.1*cm))
    elements.append(Paragraph(
        "&nbsp;&nbsp;-&nbsp;&nbsp;Au code du travail Luxembourgeois Livre II, Chapitre III Art.L233-1 à Art.L234-77.",
        style_recommand
    ))
    elements.append(Paragraph(
        "&nbsp;&nbsp;-&nbsp;&nbsp;Au contrat collectif pour le personnel conclu entre SOCOM SA et la délégation",
        style_recommand
    ))

    # Pied de page
    def _on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(2*cm, 1*cm, "demande de congé")
        canvas.drawRightString(A4[0] - 2*cm, 1*cm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(elements, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()


# ──────────────────────────────────────────────────────────────
# Test local : génère un exemple
# ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    sample = {
        "nom_complet": "SALMON David",
        "matricule": "2507",
        "date_demande": "16/03/2026",
        "date_debut": "05/06/2026",
        "date_fin": "05/06/2026",
        "nb_jours": "1 jour",
        "motif": "LEGAL",
        "commentaire": "",
        "responsable_nom": "SALMON Nicolas",
        "responsable_decision": "ACCORD",
        "responsable_date": "17/03/2026",
        "directeur_nom": "",
        "directeur_decision": "",
        "directeur_date": "",
    }
    pdf = generate_demande_conge_pdf(sample)
    with open('test_demande_conge.pdf', 'wb') as f:
        f.write(pdf)
    print(f"PDF généré : test_demande_conge.pdf ({len(pdf)} octets)")
