
import io
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.utils import ImageReader
from PIL import Image as PILImage
import os

W, H = A4
BLUE  = colors.HexColor('#244298')
LGREY = colors.HexColor('#f1f5f9')
DGREY = colors.HexColor('#1e293b')

LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'socom_logo.png')

def _logo_dims():
    pil = PILImage.open(LOGO_PATH)
    w, h = pil.size
    lw = 42*mm
    lh = lw * h / w
    return lw, lh, w, h

def _draw_header(c, doc, data, first=True):
    c.saveState()
    h_height = 44*mm if first else 18*mm
    c.setFillColor(BLUE)
    c.rect(0, H-h_height, W, h_height, fill=1, stroke=0)
    lw, lh, lpx, lhpx = _logo_dims()
    if first:
        logo = ImageReader(LOGO_PATH)
        ly = H - 13*mm - lh
        c.drawImage(logo, 12*mm, ly, width=lw, height=lh, preserveAspectRatio=True, mask='auto')
        text = "solutions technologiques"
        fs = 7.0 * (lw / c.stringWidth(text, "Helvetica", 7.0))
        c.setFillColor(colors.HexColor('#bfdbfe'))
        c.setFont("Helvetica", fs)
        c.drawString(12*mm, ly - 4*mm, text)
        infos = ["SOCOM S.A.", "10 rue du Commerce", "L-3895 FOETZ", "T +352 55 14 15-1", "socom@socom.lu"]
        y = H - 13*mm
        c.setFont("Helvetica", 7.5)
        for l in infos:
            c.drawRightString(W-12*mm, y, l)
            y -= 4.5*mm
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 13)
        titre = data.get('titre_rapport', "RAPPORT D'INTERVENTION")
        c.drawCentredString(W/2, H-41*mm, titre)
    else:
        logo = ImageReader(LOGO_PATH)
        lw2 = 22*mm
        lh2 = lw2 * lhpx / lpx
        c.drawImage(logo, 12*mm, H-h_height/2-lh2/2, width=lw2, height=lh2, preserveAspectRatio=True, mask='auto')
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(W/2, H-11*mm, f"{data.get('client','')} — {data.get('numero_projet','')}")
        c.setFont("Helvetica", 8)
        c.drawRightString(W-12*mm, H-11*mm, data.get('titre','Rapport'))
    c.setFillColor(BLUE)
    c.rect(0, 0, W, 12*mm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica", 7)
    c.setFont("Helvetica", 6.5)
    c.drawCentredString(W/2, 7*mm, "SOCOM Société Anonyme — 10 rue du Commerce — L-3895 FOETZ — T +352 55 14 15-1 — socom@socom.lu")
    c.drawCentredString(W/2, 3.5*mm, "R.C. B49898 Luxembourg — Autorisation d'établissement N°117706 — N° d'identification TVA LU16208516")
    c.setFont("Helvetica", 7)
    c.drawRightString(W-5*mm, 5*mm, f"Page {doc.page}")
    c.restoreState()

def generate_rapport(data):
    """
    data dict keys:
      titre_rapport, titre, client, numero_projet, numero_iv,
      type_label, date, equipement, localisation, intervenants,
      intervenants_list, observations, actions_realisees,
      mesures, recommandations, conclusion
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=12*mm, rightMargin=12*mm,
        topMargin=50*mm, bottomMargin=18*mm)

    def h1(txt):
        return Paragraph(f'<b>{txt}</b>',
            ParagraphStyle('h1', fontSize=10, textColor=BLUE,
                spaceBefore=8, spaceAfter=3, backColor=colors.HexColor('#eff6ff'),
                leftIndent=2, borderPad=3))
    def body(txt):
        return Paragraph(txt, ParagraphStyle('body', fontSize=9,
            spaceAfter=3, textColor=DGREY, leading=14))
    def sep():
        return HRFlowable(width="100%", thickness=0.5, color=BLUE, spaceAfter=4, spaceBefore=1)

    story = []
    lbl = ParagraphStyle('lbl', fontSize=8, textColor=BLUE, fontName='Helvetica-Bold')
    val = ParagraphStyle('val', fontSize=9, textColor=DGREY)

    # Bloc identification
    info_data = [
        [Paragraph('Client', lbl), Paragraph(data.get('client','--'), val),
         Paragraph("Date d'intervention", lbl), Paragraph(data.get('date','--'), val)],
        [Paragraph('N° de projet', lbl), Paragraph(data.get('numero_projet','--'), val),
         Paragraph('Référence GMAO', lbl), Paragraph(data.get('numero_iv','--'), val)],
        [Paragraph('Équipement', lbl), Paragraph(data.get('equipement','--'), val),
         Paragraph('Localisation', lbl), Paragraph(data.get('localisation','--'), val)],
        [Paragraph('Type', lbl), Paragraph(data.get('type_label','--'), val),
         Paragraph('Intervenant(s)', lbl), Paragraph(data.get('intervenants','--'), val)],
    ]
    t = Table(info_data, colWidths=[38*mm, 62*mm, 40*mm, 46*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), LGREY),
        ('BACKGROUND', (2,0), (2,-1), LGREY),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t)
    story.append(Spacer(1, 4*mm))

    # Intervenants
    if data.get('intervenants_list'):
        story.append(h1("INTERVENANTS"))
        story.append(sep())
        th = ParagraphStyle('th', fontSize=8, textColor=colors.white, fontName='Helvetica-Bold')
        iv_data = [[Paragraph('Nom',th), Paragraph('Date',th),
                    Paragraph('Heure début',th), Paragraph('Heure fin',th), Paragraph('Durée',th)]]
        for iv in data['intervenants_list']:
            iv_data.append([iv.get('nom','--'), iv.get('date','--'),
                iv.get('heure_debut','--'), iv.get('heure_fin','--'),
                f"{iv.get('total_heures',0)}h"])
        t2 = Table(iv_data, colWidths=[65*mm, 28*mm, 22*mm, 22*mm, 21*mm])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BLUE),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LGREY]),
            ('PADDING', (0,0), (-1,-1), 5),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t2)
        story.append(Spacer(1, 2*mm))

    # Sections
    for key, titre in [
        ('observations',      "OBSERVATIONS"),
        ('actions_realisees', "ACTIONS RÉALISÉES"),
        ('mesures',           "MESURES RELEVÉES"),
        ('recommandations',   "RECOMMANDATIONS / PRÉCONISATIONS"),
        ('conclusion',        "CONCLUSION"),
    ]:
        if data.get(key):
            story.append(h1(titre))
            story.append(sep())
            story.append(body(data[key].replace('\n','<br/>')))
            story.append(Spacer(1, 2*mm))

    # Signatures
    story.append(Spacer(1, 8*mm))
    sig_lbl = ParagraphStyle('sigl', fontSize=8, textColor=BLUE, fontName='Helvetica-Bold', alignment=TA_CENTER)
    sig_data = [
        [Paragraph('Signature Technicien', sig_lbl), '', Paragraph("Signature Client / Donneur d'ordre", sig_lbl)],
        [' ',' ',' '], [' ',' ',' '], [' ',' ',' '],
    ]
    sig_t = Table(sig_data, colWidths=[70*mm, 20*mm, 70*mm-6])
    sig_t.setStyle(TableStyle([
        ('BOX', (0,0), (0,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('BOX', (2,0), (2,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('BACKGROUND', (0,0), (0,0), LGREY),
        ('BACKGROUND', (2,0), (2,0), LGREY),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 5),
        ('ROWHEIGHT', (0,1), (-1,-1), 8*mm),
    ]))
    story.append(sig_t)

    doc.build(story,
        onFirstPage=lambda c,d: _draw_header(c,d,data,first=True),
        onLaterPages=lambda c,d: _draw_header(c,d,data,first=False))
    buf.seek(0)
    return buf.read()
