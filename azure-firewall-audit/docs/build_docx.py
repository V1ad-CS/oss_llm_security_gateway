#!/usr/bin/env python3
"""
Builds the Word versions of the documentation from the Markdown sources in this
directory:

    python docs/build_docx.py

Needs pandoc 3.x on PATH. pandoc converts the Markdown; the result is then
restyled to match docs/security-gateway-and-guardrail.ru.docx (Arial, dark blue
headings, tables with a light blue header row, A4 with 2 cm margins, footer with
page numbers), so all project documents look alike. The first heading becomes
the document title and the line under it the subtitle.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTPUT_DIR = HERE.parents[1] / "docs"

# Markdown source, Word file in OUTPUT_DIR, footer text
DOCUMENTS = (
    ("requirements.md", "azure-firewall-audit-requirements.ru.docx", "Аудит Azure Firewall и NSG · требования"),
    ("description.md", "azure-firewall-audit-description.ru.docx", "Аудит Azure Firewall и NSG · описание решения"),
)

TEXT_WIDTH = 9638  # A4 width minus two 2 cm margins, in twentieths of a point
EMU_PER_TWIP = 635
FOOTER_REL_ID = "rIdAzfwFooter"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

ARIAL = '<w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Arial" w:cs="Arial"/>'
CONSOLAS = '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Consolas" w:cs="Consolas"/>'
BORDER = 'w:val="single" w:sz="4" w:space="0" w:color="BFC7D5"'
TABLE_BORDERS = (
    f"<w:tblBorders><w:top {BORDER}/><w:left {BORDER}/><w:bottom {BORDER}/><w:right {BORDER}/>"
    f"<w:insideH {BORDER}/><w:insideV {BORDER}/></w:tblBorders>"
)
CELL_MARGINS = (
    '<w:tblCellMar><w:top w:w="70" w:type="dxa"/><w:left w:w="110" w:type="dxa"/>'
    '<w:bottom w:w="70" w:type="dxa"/><w:right w:w="110" w:type="dxa"/></w:tblCellMar>'
)
HEADER_FILL = '<w:shd w:val="clear" w:color="auto" w:fill="DCE6F4"/>'
HEADER_RUN = '<w:b/><w:bCs/><w:color w:val="1E3A6E"/>'

DOC_DEFAULTS = (
    "<w:docDefaults><w:rPrDefault><w:rPr>" + ARIAL +
    '<w:color w:val="1F2937"/><w:sz w:val="21"/><w:szCs w:val="21"/>'
    '<w:lang w:val="ru-RU" w:eastAsia="en-US" w:bidi="ar-SA"/></w:rPr></w:rPrDefault>'
    '<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault>'
    "</w:docDefaults>"
)


def _paragraph_style(style_id: str, name: str, ppr: str = "", rpr: str = "", based_on: str = "Normal", custom: bool = False) -> str:
    custom_attr = ' w:customStyle="1"' if custom else ""
    return (
        f'<w:style w:type="paragraph"{custom_attr} w:styleId="{style_id}"><w:name w:val="{name}"/>'
        f'<w:basedOn w:val="{based_on}"/><w:qFormat/>'
        f"{f'<w:pPr>{ppr}</w:pPr>' if ppr else ''}{f'<w:rPr>{rpr}</w:rPr>' if rpr else ''}</w:style>"
    )


def _heading(level: int, size: int, color: str, before: int, after: int) -> str:
    return _paragraph_style(
        f"Heading{level}", f"heading {level}",
        f'<w:keepNext/><w:keepLines/><w:spacing w:before="{before}" w:after="{after}"/><w:outlineLvl w:val="{level - 1}"/>',
        f'{ARIAL}<w:b/><w:bCs/><w:color w:val="{color}"/><w:sz w:val="{size}"/><w:szCs w:val="{size}"/>',
    )


STYLES = {
    "Title": _paragraph_style(
        "Title", "Title", '<w:keepNext/><w:spacing w:before="480" w:after="120"/>',
        '<w:b/><w:bCs/><w:color w:val="1F3864"/><w:sz w:val="40"/><w:szCs w:val="40"/>'),
    "Subtitle": _paragraph_style(
        "Subtitle", "Subtitle",
        '<w:pBdr><w:bottom w:val="single" w:sz="8" w:space="6" w:color="2F5D9F"/></w:pBdr><w:spacing w:before="0" w:after="360"/>',
        '<w:color w:val="6B7280"/><w:sz w:val="20"/><w:szCs w:val="20"/>'),
    "Heading1": _heading(1, 30, "1F3864", 400, 160),
    "Heading2": _heading(2, 24, "2F5496", 280, 120),
    "Heading3": _heading(3, 22, "1F4D78", 200, 80),
    "BodyText": _paragraph_style("BodyText", "Body Text", '<w:spacing w:before="0" w:after="120"/>'),
    "FirstParagraph": _paragraph_style("FirstParagraph", "First Paragraph", based_on="BodyText", custom=True),
    "Compact": _paragraph_style("Compact", "Compact", '<w:spacing w:before="0" w:after="40"/>', based_on="BodyText", custom=True),
    "TableText": _paragraph_style(
        "TableText", "Table Text", '<w:spacing w:before="0" w:after="0" w:line="252" w:lineRule="auto"/>',
        '<w:sz w:val="18"/><w:szCs w:val="18"/>', custom=True),
    "SourceCode": _paragraph_style(
        "SourceCode", "Source Code",
        '<w:shd w:val="clear" w:color="auto" w:fill="F3F4F6"/><w:spacing w:before="60" w:after="160" w:line="240" w:lineRule="auto"/>'
        '<w:ind w:left="113" w:right="113"/>',
        f'{CONSOLAS}<w:sz w:val="17"/><w:szCs w:val="17"/>', custom=True),
    "CaptionedFigure": _paragraph_style(
        "CaptionedFigure", "Captioned Figure", '<w:keepNext/><w:spacing w:before="160" w:after="60"/><w:jc w:val="center"/>', custom=True),
    "ImageCaption": _paragraph_style(
        "ImageCaption", "Image Caption", '<w:spacing w:before="0" w:after="240"/><w:jc w:val="center"/>',
        '<w:i/><w:iCs/><w:color w:val="4B5563"/><w:sz w:val="18"/><w:szCs w:val="18"/>', custom=True),
    "VerbatimChar": (
        '<w:style w:type="character" w:customStyle="1" w:styleId="VerbatimChar"><w:name w:val="Verbatim Char"/>'
        f'<w:basedOn w:val="DefaultParagraphFont"/><w:rPr>{CONSOLAS}<w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>'
    ),
    "Hyperlink": (
        '<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink"/>'
        '<w:basedOn w:val="DefaultParagraphFont"/><w:rPr><w:color w:val="2F5496"/><w:u w:val="single"/></w:rPr></w:style>'
    ),
    "Table": (
        '<w:style w:type="table" w:default="1" w:styleId="Table"><w:name w:val="Table"/><w:qFormat/>'
        f"<w:tblPr>{TABLE_BORDERS}{CELL_MARGINS}</w:tblPr>"
        f'<w:tblStylePr w:type="firstRow"><w:rPr>{HEADER_RUN}</w:rPr><w:tcPr>{HEADER_FILL}</w:tcPr></w:tblStylePr></w:style>'
    ),
}


def footer_xml(text: str) -> str:
    rpr = '<w:rPr><w:color w:val="6B7280"/><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr>'

    def run(body: str) -> str:
        return f"<w:r>{rpr}{body}</w:r>"

    def field(name: str) -> str:
        return (run('<w:fldChar w:fldCharType="begin"/>') + run(f'<w:instrText xml:space="preserve"> {name} </w:instrText>')
                + run('<w:fldChar w:fldCharType="separate"/>') + run("<w:t>1</w:t>") + run('<w:fldChar w:fldCharType="end"/>'))

    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:ftr xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:p><w:pPr>'
        '<w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="BFC7D5"/></w:pBdr>'
        f'<w:tabs><w:tab w:val="right" w:pos="{TEXT_WIDTH}"/></w:tabs><w:spacing w:after="0"/></w:pPr>'
        + run(f'<w:t xml:space="preserve">{text}</w:t>') + run("<w:tab/>") + run('<w:t xml:space="preserve">Стр. </w:t>')
        + field("PAGE") + run('<w:t xml:space="preserve"> из </w:t>') + field("NUMPAGES")
        + "</w:p></w:ftr>"
    )


SECTION = (
    f'<w:sectPr><w:footerReference w:type="default" r:id="{FOOTER_REL_ID}"/>'
    '<w:pgSz w:w="11906" w:h="16838"/>'
    '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/>'
    "</w:sectPr>"
)


# pandoc 3.1 writes a few elements out of schema order (and a stray "&gt;" in
# one of its built-in styles). Word tolerates it, strict validators do not.

# Order of w:settings children in the WordprocessingML schema (CT_Settings).
SETTINGS_ORDER = """
writeProtection view zoom removePersonalInformation removeDateAndTime doNotDisplayPageBoundaries
displayBackgroundShape printPostScriptOverText printFractionalCharacterWidth printFormsData
embedTrueTypeFonts embedSystemFonts saveSubsetFonts saveFormsData mirrorMargins alignBordersAndEdges
bordersDoNotSurroundHeader bordersDoNotSurroundFooter gutterAtTop hideSpellingErrors
hideGrammaticalErrors activeWritingStyle proofState formsDesign attachedTemplate linkStyles
stylePaneFormatFilter stylePaneSortMethod documentType mailMerge revisionView trackRevisions
doNotTrackMoves doNotTrackFormatting documentProtection autoFormatOverride styleLockTheme
styleLockQFSet defaultTabStop autoHyphenation consecutiveHyphenLimit hyphenationZone
doNotHyphenateCaps showEnvelope summaryLength clickAndTypeStyle defaultTableStyle evenAndOddHeaders
bookFoldRevPrinting bookFoldPrinting bookFoldPrintingSheets drawingGridHorizontalSpacing
drawingGridVerticalSpacing displayHorizontalDrawingGridEvery displayVerticalDrawingGridEvery
doNotUseMarginsForDrawingGridOrigin drawingGridHorizontalOrigin drawingGridVerticalOrigin
doNotShadeFormData noPunctuationKerning characterSpacingControl printTwoOnOne
strictFirstAndLastChars noLineBreaksAfter noLineBreaksBefore savePreviewPicture
doNotValidateAgainstSchema saveInvalidXml ignoreMixedContent alwaysShowPlaceholderText
doNotDemarcateInvalidXml saveXmlDataOnly useXSLTWhenSaving saveThroughXslt showXMLTags
alwaysMergeEmptyNamespace updateFields hdrShapeDefaults footnotePr endnotePr compat docVars rsids
mathPr attachedSchema themeFontLang clrSchemeMapping doNotIncludeSubdocsInStats
doNotAutoCompressPictures forceUpgrade captions readModeInkLockDown smartTagType schemaLibrary
shapeDefaults doNotEmbedSmartTags decimalSymbol listSeparator
""".split()


def _sort_settings(xml: str) -> str:
    match = re.search(r"(<w:settings\b[^>]*>)(.*)(</w:settings>)", xml, re.S)
    if not match:
        return xml
    children = [m.group(0) for m in re.finditer(r"<(\w+):(\w+)\b[^>]*?(?:/>|>.*?</\1:\2>)", match.group(2), re.S)]

    def rank(element: str) -> tuple[int, int]:
        prefix, name = re.match(r"<(\w+):(\w+)", element).groups()
        # m:mathPr is part of the list; extension elements (w14:, w15:) go last.
        return (SETTINGS_ORDER.index(name) if prefix in ("w", "m") and name in SETTINGS_ORDER else len(SETTINGS_ORDER), 0)

    children.sort(key=rank)  # stable: unknown elements keep their order
    return xml[:match.start()] + match.group(1) + "".join(children) + match.group(3) + xml[match.end():]


def _reorder_ppr(match: re.Match) -> str:
    ppr = match.group(0)
    jc = re.search(r"<w:jc [^>]*/>", ppr)
    spacing = re.search(r"<w:spacing [^>]*/>", ppr)
    if jc and spacing and jc.start() < spacing.start():
        ppr = ppr.replace(jc.group(0), "", 1).replace(spacing.group(0), spacing.group(0) + jc.group(0), 1)
    return ppr


def fix_schema_order(files: dict[str, bytes]) -> None:
    styles = files["word/styles.xml"].decode("utf-8")
    styles = re.sub(r"(<w:rPr>(?:(?!</w:rPr>).)*?/>)\s*&gt;", r"\1", styles, flags=re.S)
    styles = re.sub(r"<w:pPr>.*?</w:pPr>", _reorder_ppr, styles, flags=re.S)
    files["word/styles.xml"] = styles.encode("utf-8")

    document = files["word/document.xml"].decode("utf-8")
    # The tempered pattern keeps the match inside one paragraph.
    document = re.sub(r"<w:pPr>(<w:numPr>(?:(?!</w:numPr>).)*</w:numPr>)(<w:pStyle [^>]*/>)", r"<w:pPr>\2\1", document, flags=re.S)
    files["word/document.xml"] = document.encode("utf-8")

    if "word/numbering.xml" in files:
        numbering = files["word/numbering.xml"].decode("utf-8")
        numbering = re.sub(r'<w:nsid w:val="([0-9A-Fa-f]+)"', lambda m: f'<w:nsid w:val="{m.group(1)[-8:].zfill(8).upper()}"', numbering)
        files["word/numbering.xml"] = numbering.encode("utf-8")

    files["word/settings.xml"] = _sort_settings(files["word/settings.xml"].decode("utf-8")).encode("utf-8")

    types = files["[Content_Types].xml"].decode("utf-8")
    if 'Extension="png"' not in types and any(name.endswith(".png") for name in files):
        types = types.replace("<Default ", '<Default Extension="png" ContentType="image/png" /><Default ', 1)
    files["[Content_Types].xml"] = types.encode("utf-8")


def restyle_styles(xml: str) -> str:
    xml = re.sub(r"<w:docDefaults>.*?</w:docDefaults>", DOC_DEFAULTS, xml, count=1, flags=re.S)
    for style_id, style in STYLES.items():
        pattern = re.compile(rf'<w:style\b[^>]*w:styleId="{style_id}"[^>]*>.*?</w:style>', re.S)
        if pattern.search(xml):
            xml = pattern.sub(lambda _: style, xml, count=1)
        else:
            xml = xml.replace("</w:styles>", style + "</w:styles>")
    return xml


def restyle_table(table: str) -> str:
    """Fixed full-width columns, borders, cell margins and a shaded header row.

    The table style already says all of this; it is repeated as direct
    formatting because LibreOffice ignores parts of table styles.
    """
    widths = [int(w) for w in re.findall(r'<w:gridCol w:w="(\d+)"\s*/>', table)]
    total = sum(widths) or 1
    widths = [max(1, round(w * TEXT_WIDTH / total)) for w in widths]
    widths[-1] += TEXT_WIDTH - sum(widths)
    grid = "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>"
    table = re.sub(r"<w:tblGrid>.*?</w:tblGrid>", grid, table, count=1, flags=re.S)
    look = re.search(r"<w:tblLook [^>]*/>", table)
    table = re.sub(
        r"<w:tblPr>.*?</w:tblPr>",
        f'<w:tblPr><w:tblStyle w:val="Table"/><w:tblW w:w="{TEXT_WIDTH}" w:type="dxa"/>{TABLE_BORDERS}'
        f'<w:tblLayout w:type="fixed"/>{CELL_MARGINS}{look.group(0) if look else ""}</w:tblPr>',
        table, count=1, flags=re.S,
    )
    table = table.replace('<w:pStyle w:val="Compact" />', '<w:pStyle w:val="TableText" />')
    # Code in tables is one point smaller than the 9 pt table text, as in the gateway document.
    table = table.replace('<w:rStyle w:val="VerbatimChar" />', '<w:rStyle w:val="VerbatimChar" /><w:sz w:val="16" /><w:szCs w:val="16" />')

    def row(match: re.Match) -> str:
        text = match.group(0)
        header = "<w:tblHeader" in text
        cells = iter(widths)
        text = re.sub(
            r"<w:tcPr\s*/>",
            lambda _: f'<w:tcPr><w:tcW w:w="{next(cells, widths[-1])}" w:type="dxa"/>{HEADER_FILL if header else ""}</w:tcPr>',
            text,
        )
        if header:
            text = text.replace("<w:trPr>", "<w:trPr><w:cantSplit/>", 1)
            text = re.sub(r"<w:r>(<w:rPr>(<w:rStyle [^>]*/>)?)?", _header_run, text)
        else:
            text = text.replace("<w:tr>", "<w:tr><w:trPr><w:cantSplit/></w:trPr>", 1)
        return text

    return re.sub(r"<w:tr>.*?</w:tr>", row, table, flags=re.S)


def _header_run(match: re.Match) -> str:
    """Bold dark blue text in a header cell; rStyle must stay first in rPr."""
    if match.group(1) is None:
        return f"<w:r><w:rPr>{HEADER_RUN}</w:rPr>"
    return f"<w:r><w:rPr>{match.group(2) or ''}{HEADER_RUN}"


def scale_images(xml: str) -> str:
    """Every figure spans the text width; pandoc sizes them by DPI."""
    target = TEXT_WIDTH * EMU_PER_TWIP

    def drawing(match: re.Match) -> str:
        text = match.group(0)
        size = re.search(r'<wp:extent cx="(\d+)" cy="(\d+)"', text)
        if not size:
            return text
        cx, cy = int(size.group(1)), int(size.group(2))
        new = f'cx="{target}" cy="{round(cy * target / cx)}"'
        return re.sub(r'cx="\d+" cy="\d+"', new, text)

    return re.sub(r"<w:drawing>.*?</w:drawing>", drawing, xml, flags=re.S)


def _space_after_table(match: re.Match) -> str:
    """Body text right under a table gets the same gap as between paragraphs."""
    ppr = match.group(2)
    if re.search(r"<w:(spacing|jc|ind|rPr|outlineLvl)\b", ppr) or "Heading" in ppr:
        return match.group(0)
    return f'{match.group(1)}{ppr}<w:spacing w:before="160" /></w:pPr>'


def restyle_document(xml: str) -> str:
    xml = re.sub(r"<w:tbl>.*?</w:tbl>", lambda m: restyle_table(m.group(0)), xml, flags=re.S)
    xml = re.sub(r"(</w:tbl>\s*<w:p>)(<w:pPr>(?:(?!</w:pPr>).)*)</w:pPr>", _space_after_table, xml, flags=re.S)
    xml = scale_images(xml)
    return re.sub(r"<w:sectPr\b[^>]*?(/>|>.*?</w:sectPr>)\s*</w:body>", SECTION + "</w:body>", xml, count=1, flags=re.S)


def add_footer(files: dict[str, bytes], text: str) -> None:
    files["word/footer1.xml"] = footer_xml(text).encode("utf-8")
    rels = files["word/_rels/document.xml.rels"].decode("utf-8")
    rels = rels.replace(
        "</Relationships>",
        f'<Relationship Id="{FOOTER_REL_ID}" Type="{R_NS}/footer" Target="footer1.xml"/></Relationships>',
    )
    files["word/_rels/document.xml.rels"] = rels.encode("utf-8")
    types = files["[Content_Types].xml"].decode("utf-8")
    types = types.replace(
        "</Types>",
        '<Override PartName="/word/footer1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>',
    )
    files["[Content_Types].xml"] = types.encode("utf-8")


def split_title(markdown: str) -> tuple[str, str]:
    """The line under the first heading becomes the subtitle."""
    match = re.match(r"(# [^\n]+\n)\n([^\n#][^\n]*)\n", markdown)
    if not match:
        return markdown, ""
    return match.group(1) + markdown[match.end():], match.group(2).strip()


def build(source: Path, target: Path, footer: str) -> None:
    markdown, subtitle = split_title(source.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "raw.docx"
        command = [
            "pandoc", "-f", "markdown", "-t", "docx", "--shift-heading-level-by=-1", "--no-highlight",
            f"--resource-path={source.parent}", "-M", "lang=ru-RU", "-o", str(raw),
        ]
        if subtitle:
            command += ["-M", f"subtitle={subtitle}"]
        subprocess.run(command, input=markdown.encode("utf-8"), check=True)
        with zipfile.ZipFile(raw) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
    files["word/styles.xml"] = restyle_styles(files["word/styles.xml"].decode("utf-8")).encode("utf-8")
    files["word/document.xml"] = restyle_document(files["word/document.xml"].decode("utf-8")).encode("utf-8")
    add_footer(files, footer)
    fix_schema_order(files)
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    print(f"записан {target}")


def main() -> int:
    if not shutil.which("pandoc"):
        print("нужен pandoc 3.x: https://pandoc.org/installing.html", file=sys.stderr)
        return 1
    for source, target, footer in DOCUMENTS:
        build(HERE / source, OUTPUT_DIR / target, footer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
