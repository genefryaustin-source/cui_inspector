"""
CUI Document Inspector and CMMC Data Flow Mapper
Designed for AWS FedRAMP Cloud Environment
Compliance with NIST SP 800-171 and CMMC 2.0 requirements
"""

import streamlit as st
import pandas as pd
import re
import json
from datetime import datetime
from typing import List, Dict, Tuple
import base64
from io import BytesIO
import hashlib
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.utils import ImageReader
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import PyPDF2
from docx import Document
import openpyxl
from pptx import Presentation
import pytesseract
from PIL import Image
import pdf2image
import tempfile
import os
import zipfile
import streamlit.components.v1 as components
import sqlite3
from pathlib import Path

# Load configuration
try:
    from config import TESSERACT_CMD, POPPLER_PATH, OCR_DPI, OCR_LANGUAGE
    # Set Tesseract command if specified in config
    if TESSERACT_CMD:
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD
except ImportError:
    # Default values if config.py not found
    POPPLER_PATH = None
    OCR_DPI = 300
    OCR_LANGUAGE = 'eng'
    # Try to auto-detect Tesseract on Windows
    if os.name == 'nt':  # Windows
        possible_paths = [
            r'C:\Program Files\Tesseract-OCR\tesseract.exe',
            r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
        ]
        for path in possible_paths:
            if os.path.exists(path):
                pytesseract.pytesseract.tesseract_cmd = path
                break

# -----------------------------
# Multi-tenant + RBAC
# -----------------------------
def _current_user():
    return st.session_state.get("auth_user")

def _current_tenant_id() -> int | None:
    return st.session_state.get("tenant_id")

def _set_current_tenant_id(tid: int | None):
    st.session_state["tenant_id"] = tid

def _is_superadmin() -> bool:
    u = _current_user()
    return bool(u) and u.get("role") == "superadmin"

def _is_tenant_admin() -> bool:
    u = _current_user()
    return bool(u) and u.get("role") == "tenant_admin"

def _is_auditor() -> bool:
    u = _current_user()
    return bool(u) and u.get("role") == "auditor"

def _has_cross_tenant_access() -> bool:
    return _is_superadmin() or _is_auditor()

def _require_login() -> bool:
    return _current_user() is not None

def ensure_default_tenant() -> int:
    init_evidence_store()
    con = _db()
    try:
        r = con.execute("SELECT id FROM tenants WHERE is_active=1 ORDER BY id ASC LIMIT 1").fetchone()
        if r:
            return int(r["id"])
        con.execute("INSERT INTO tenants (name, created_at, is_active) VALUES (?, ?, 1)", ("default", _now_iso()))
        con.commit()
        return int(con.execute("SELECT id FROM tenants WHERE name='default'").fetchone()["id"])
    finally:
        con.close()

def list_tenants(active_only: bool = True):
    init_evidence_store()
    con = _db()
    try:
        if active_only:
            rows = con.execute("SELECT id, name FROM tenants WHERE is_active=1 ORDER BY name").fetchall()
        else:
            rows = con.execute("SELECT id, name, is_active FROM tenants ORDER BY name").fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()

def render_tenant_selector_sidebar():
    ensure_default_tenant()
    u = _current_user()
    if not u:
        return
    tenants = list_tenants(active_only=True)
    if not tenants:
        return

    if _has_cross_tenant_access():
        opts = {t["name"]: int(t["id"]) for t in tenants}
        if _current_tenant_id() is None:
            _set_current_tenant_id(list(opts.values())[0])
        inv = {v:k for k,v in opts.items()}
        cur_name = inv.get(_current_tenant_id(), list(opts.keys())[0])
        choice = st.sidebar.selectbox("Tenant", options=list(opts.keys()), index=list(opts.keys()).index(cur_name))
        _set_current_tenant_id(opts[choice])
    else:
        if u.get("tenant_id") is None:
            _set_current_tenant_id(ensure_default_tenant())
        else:
            _set_current_tenant_id(int(u["tenant_id"]))
        tname = next((t["name"] for t in tenants if int(t["id"]) == int(_current_tenant_id())), "default")
        st.sidebar.markdown(f"**Tenant:** {tname}")



# Page configuration
st.set_page_config(
    page_title="CUI Inspector & CMMC Data Flow Mapper",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CUI Categories and Markings (NIST SP 800-171 & 32 CFR Part 2002)
CUI_CATEGORIES = {
    "CUI": ["Controlled Unclassified Information"],
    "CUI//SP-EXPT": ["Export Controlled"],
    "CUI//SP-PRVCY": ["Privacy Information"],
    "CUI//SP-PROPIN": ["Proprietary Information"],
    "CUI//FEDCON": ["Federal Contract Information"],
    "CUI//SP-CTI": ["Critical Infrastructure Information"],
    "CUI//SP-ITAR": ["International Traffic in Arms Regulations"],
    "CUI//SP-PROCURE": ["Procurement Information"],
    "CUI//SP-LEGAL": ["Legal Information"],
    "CUI//SP-TAX": ["Tax Information"]
}

# CUI Detection Patterns
CUI_PATTERNS = {
    "CUI_MARKING": r'\b(CUI|CONTROLLED)\b',
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
    "EXPORT_CONTROL": r'\b(ITAR|EAR|Export[- ]Control)\b',
    "PROPRIETARY": r'\b(PROPRIETARY|CONFIDENTIAL|COMPANY CONFIDENTIAL)\b',
    "FEDERAL_CONTRACT": r'\b(FAR|DFARS|Contract[- ]Number|CDRL)\b',
    "PRIVACY": r'\b(PII|Personally[- ]Identifiable[- ]Information|PHI)\b',
    "TECHNICAL_DATA": r'\b(Technical[- ]Data|TD|Engineering[- ]Data)\b',
    "FINANCIAL": r'\b(Financial[- ]Information|Budget|Cost[- ]Data)\b',
    "IP_ADDRESS": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
}


class CUIInspector:
    """Inspects documents for CUI content"""
    
    def __init__(self):
        self.findings = []
    
    def extract_text_from_pdf(self, file) -> str:
        """Extract text from PDF file with OCR fallback for scanned documents"""
        text = ""
        is_scanned = False
        
        try:
            # First, try standard text extraction with PyPDF2
            pdf_reader = PyPDF2.PdfReader(file)
            
            for page_num, page in enumerate(pdf_reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
            
            # Check if we got meaningful text (more than just whitespace/newlines)
            if len(text.strip()) < 50:  # Threshold for likely scanned document
                is_scanned = True
                st.info(f"📸 Document appears to be scanned/image-based. Applying OCR...")
        except Exception as e:
            st.warning(f"⚠️ Standard PDF extraction failed: {str(e)}. Trying OCR...")
            is_scanned = True
        
        # If document is scanned or text extraction failed, use OCR
        if is_scanned:
            try:
                # Reset file pointer
                file.seek(0)
                
                # Create temporary file for pdf2image
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
                    tmp_file.write(file.read())
                    tmp_path = tmp_file.name
                
                try:
                    # Convert PDF pages to images
                    if POPPLER_PATH:
                        images = pdf2image.convert_from_path(tmp_path, dpi=OCR_DPI, poppler_path=POPPLER_PATH)
                    else:
                        images = pdf2image.convert_from_path(tmp_path, dpi=OCR_DPI)
                    
                    # Apply OCR to each page
                    ocr_text = ""
                    progress_placeholder = st.empty()
                    
                    for idx, image in enumerate(images):
                        progress_placeholder.text(f"🔍 OCR processing page {idx + 1}/{len(images)}...")
                        page_text = pytesseract.image_to_string(image, lang=OCR_LANGUAGE)
                        ocr_text += f"\n--- Page {idx + 1} ---\n{page_text}\n"
                    
                    progress_placeholder.empty()
                    text = ocr_text if ocr_text.strip() else text
                    
                    if ocr_text.strip():
                        st.success(f"✅ OCR completed: {len(images)} page(s) processed")
                
                finally:
                    # Clean up temporary file
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                        
            except Exception as ocr_error:
                st.error(f"❌ OCR failed: {str(ocr_error)}")
                if not text:
                    raise Exception(f"Could not extract text from PDF: {str(ocr_error)}")
        
        if not text.strip():
            raise Exception("No text could be extracted from PDF")
        
        return text
    
    def generate_cui_report_pdf(self, findings: Dict, output_path: str):
        """Generate a PDF report of CUI findings using ReportLab"""
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph("🔒 CUI Inspection Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Document information
        story.append(Paragraph(f"<b>Document:</b> {findings['filename']}", styles['Normal']))
        story.append(Paragraph(f"<b>Inspection Date:</b> {findings['timestamp']}", styles['Normal']))
        story.append(Paragraph(f"<b>CUI Detected:</b> {'Yes' if findings['cui_detected'] else 'No'}", styles['Normal']))
        story.append(Paragraph(f"<b>Risk Level:</b> {findings['risk_level']}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Risk level indicator
        risk_colors_map = {
            'LOW': colors.green,
            'MEDIUM': colors.orange,
            'HIGH': colors.red
        }
        risk_color = risk_colors_map.get(findings['risk_level'], colors.grey)
        
        risk_table = Table([[f"Risk Level: {findings['risk_level']}"]], colWidths=[6*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('PADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Detected Patterns
        if findings['patterns_found']:
            story.append(Paragraph("Detected Patterns", heading_style))
            pattern_data = [['Pattern Type', 'Occurrences']]
            for pattern, count in findings['patterns_found'].items():
                pattern_data.append([pattern, str(count)])
            
            pattern_table = Table(pattern_data, colWidths=[4*inch, 2*inch])
            pattern_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            story.append(pattern_table)
            story.append(Spacer(1, 0.3*inch))
        
        # CUI Categories
        if findings['cui_categories']:
            story.append(Paragraph("CUI Categories Identified", heading_style))
            for category in set(findings['cui_categories']):
                story.append(Paragraph(f"• {category}", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
        
        # Recommendations
        story.append(Paragraph("CMMC Compliance Recommendations", heading_style))
        for rec in findings['recommendations']:
            # Remove emoji for PDF
            rec_clean = re.sub(r'[^\x00-\x7F]+', '', rec)
            story.append(Paragraph(f"• {rec_clean}", styles['Normal']))
        
        story.append(Spacer(1, 0.5*inch))
        
        # Footer
        story.append(Paragraph(
            "<i>This report assists with CMMC compliance documentation but does not replace professional assessment.</i>",
            styles['Italic']
        ))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def extract_text_from_docx(self, file) -> str:
        """Extract text from Word document"""
        try:
            doc = Document(file)
            text = ""
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
            # Also extract text from tables
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        text += cell.text + " "
                text += "\n"
            return text
        except Exception as e:
            raise Exception(f"Error extracting Word text: {str(e)}")
    
    def extract_text_from_xlsx(self, file) -> str:
        """Extract text from Excel file"""
        try:
            workbook = openpyxl.load_workbook(file)
            text = ""
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                text += f"Sheet: {sheet_name}\n"
                for row in sheet.iter_rows(values_only=True):
                    row_text = " ".join([str(cell) for cell in row if cell is not None])
                    text += row_text + "\n"
            return text
        except Exception as e:
            raise Exception(f"Error extracting Excel text: {str(e)}")
    
    def extract_text_from_pptx(self, file) -> str:
        """Extract text from PowerPoint file"""
        try:
            prs = Presentation(file)
            text = ""
            for slide_num, slide in enumerate(prs.slides, 1):
                text += f"Slide {slide_num}:\n"
                for shape in slide.shapes:
                    if hasattr(shape, "text"):
                        text += shape.text + "\n"
            return text
        except Exception as e:
            raise Exception(f"Error extracting PowerPoint text: {str(e)}")
    
    def extract_text_from_file(self, file, filename: str) -> str:
        """Extract text from various file types"""
        file_extension = filename.lower().split('.')[-1]
        
        if file_extension == 'pdf':
            return self.extract_text_from_pdf(file)
        elif file_extension in ['docx', 'doc']:
            return self.extract_text_from_docx(file)
        elif file_extension in ['xlsx', 'xls']:
            return self.extract_text_from_xlsx(file)
        elif file_extension in ['pptx', 'ppt']:
            return self.extract_text_from_pptx(file)
        elif file_extension in ['txt', 'csv', 'json', 'md']:
            # Text files - decode directly
            try:
                return file.read().decode('utf-8')
            except:
                file.seek(0)
                return file.read().decode('latin-1')
        else:
            raise Exception(f"Unsupported file type: {file_extension}")
    
    def inspect_file(self, file, filename: str) -> Dict:
        """Inspect a file for CUI content"""
        try:
            # Extract text from file
            text = self.extract_text_from_file(file, filename)
            
            # Inspect the extracted text
            return self.inspect_text(text, filename)
        except Exception as e:
            return {
                'filename': filename,
                'timestamp': datetime.now().isoformat(),
                'cui_detected': False,
                'error': str(e),
                'cui_categories': [],
                'patterns_found': {},
                'risk_level': 'ERROR',
                'recommendations': [f"❌ Error processing file: {str(e)}"]
            }
    
    def inspect_text(self, text: str, filename: str) -> Dict:
        """Inspect text content for CUI indicators"""
        findings = {
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'cui_detected': False,
            'cui_categories': [],
            'patterns_found': {},
            'risk_level': 'LOW',
            'recommendations': []
        }
        
        # Check for CUI patterns
        for pattern_name, pattern in CUI_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings['cui_detected'] = True
                findings['patterns_found'][pattern_name] = len(matches)
                
                # Categorize CUI type
                if pattern_name == "CUI_MARKING":
                    findings['cui_categories'].append("Explicitly Marked CUI")
                elif pattern_name == "SSN":
                    findings['cui_categories'].append("Privacy Information (PII)")
                elif pattern_name in ["EXPORT_CONTROL", "PROPRIETARY"]:
                    findings['cui_categories'].append("Export Controlled/Proprietary")
                elif pattern_name == "FEDERAL_CONTRACT":
                    findings['cui_categories'].append("Federal Contract Information")
                elif pattern_name == "PRIVACY":
                    findings['cui_categories'].append("Privacy Information")
        
        # Determine risk level
        findings['risk_level'] = self._calculate_risk_level(findings)
        
        # Generate recommendations
        findings['recommendations'] = self._generate_recommendations(findings)
        
        return findings
    
    def _calculate_risk_level(self, findings: Dict) -> str:
        """Calculate risk level based on findings"""
        if not findings['cui_detected']:
            return 'LOW'
        
        pattern_count = sum(findings['patterns_found'].values())
        category_count = len(findings['cui_categories'])
        
        if pattern_count > 10 or category_count > 3:
            return 'HIGH'
        elif pattern_count > 5 or category_count > 1:
            return 'MEDIUM'
        else:
            return 'MEDIUM'
    
    def _generate_recommendations(self, findings: Dict) -> List[str]:
        """Generate CMMC compliance recommendations"""
        recommendations = []
        
        if findings['cui_detected']:
            recommendations.append("🔒 Apply appropriate CUI markings per NIST SP 800-171")
            recommendations.append("🔐 Implement encryption at rest (CMMC AC.3.018)")
            recommendations.append("🔑 Implement encryption in transit (CMMC SC.3.177)")
            recommendations.append("📋 Document in System Security Plan (SSP)")
            recommendations.append("🔍 Include in data flow diagram")
            recommendations.append("👥 Restrict access to authorized personnel (CMMC AC.1.001)")
            recommendations.append("📝 Maintain audit logs (CMMC AU.2.041)")
            
            if 'Export Controlled' in str(findings['cui_categories']):
                recommendations.append("⚠️ CRITICAL: Implement ITAR/EAR compliance controls")
            if 'Privacy Information' in str(findings['cui_categories']):
                recommendations.append("🛡️ Implement privacy controls per NIST SP 800-171 3.13")
        else:
            recommendations.append("✅ No CUI detected - standard security controls apply")
        
        return recommendations


class DataFlowMapper:
    """Creates CMMC-compliant data flow diagrams"""
    
    def __init__(self):
        self.flows = []
    
    def add_flow(self, source: str, destination: str, data_type: str,
                 cui_present: bool, encryption: str, controls: List[str]):
        """Add a data flow"""
        flow = {
            'id': len(self.flows) + 1,
            'source': source,
            'destination': destination,
            'data_type': data_type,
            'cui_present': cui_present,
            'encryption': encryption,
            'controls': controls,
            'cmmc_level': self._determine_cmmc_level(cui_present),
            'timestamp': datetime.now().isoformat()
        }
        self.flows.append(flow)
        return flow
    
    def _determine_cmmc_level(self, cui_present: bool) -> str:
        """Determine required CMMC level"""
        if cui_present:
            return "Level 2 (Minimum for CUI)"
        else:
            return "Level 1 (Basic Cyber Hygiene)"
    
    def generate_mermaid_diagram(self) -> str:
        """Generate Mermaid diagram for data flows"""
        diagram = "graph LR\n"
        
        for flow in self.flows:
            source = flow['source'].replace(' ', '_')
            dest = flow['destination'].replace(' ', '_')
            
            # Add CUI indicator
            cui_marker = "🔒CUI" if flow['cui_present'] else ""
            encryption_marker = "🔐" if flow['encryption'] != "None" else ""
            label = f"{flow['data_type']}<br/>{cui_marker}{encryption_marker}"
            
            diagram += f"    {source}[{flow['source']}] -->|{label}| {dest}[{flow['destination']}]\n"
            
            # Add styling for CUI flows
            if flow['cui_present']:
                diagram += f"    style {source} fill:#ff9999,stroke:#cc0000,stroke-width:3px\n"
                diagram += f"    style {dest} fill:#ff9999,stroke:#cc0000,stroke-width:3px\n"
        
        return diagram
    
    def export_to_json(self) -> str:
        """Export data flows to JSON"""
        export_data = {
            'generated': datetime.now().isoformat(),
            'total_flows': len(self.flows),
            'cui_flows': sum(1 for f in self.flows if f['cui_present']),
            'flows': self.flows
        }
        return json.dumps(export_data, indent=2)


def render_header():
    if not _require_login():
        render_login()
        return:
    """Render application header"""
    st.title("🔒 CUI Document Inspector & CMMC Data Flow Mapper")
    st.markdown("""
    **Compliance Framework:** NIST SP 800-171, CMMC 2.0, FedRAMP
    **Environment:** AWS GovCloud (FedRAMP Authorized)
    """)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("CMMC Standard", "2.0")
    with col2:
        st.metric("NIST Framework", "SP 800-171 Rev 2")
    with col3:
        st.metric("Cloud Environment", "AWS FedRAMP")
    
    st.divider()


def render_cui_inspector():
    """Render CUI inspection interface"""
    st.header("📄 CUI Document Inspector")

    autosave = st.toggle("Auto-save evidence to SQLite (recommended)", value=True)
    uploaded_by = st.text_input("Uploaded/Run by (optional)", value="")
    st.info("""
    **Purpose:** Scan documents for Controlled Unclassified Information (CUI) to ensure proper handling per NIST SP 800-171.
    **Supported Formats:** PDF, Word (DOCX), Excel (XLSX), PowerPoint (PPTX), Text files (TXT, CSV, JSON, MD)
    """)
    
    inspector = CUIInspector()
    
    # File upload
    uploaded_files = st.file_uploader(
        "Upload documents for CUI inspection",
        accept_multiple_files=True,
        type=['txt', 'csv', 'json', 'md', 'pdf', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt'],
        help="Upload documents to scan for CUI content. Supports: PDF, Word, Excel, PowerPoint, and text files"
    )
    
    # Manual text input option
    with st.expander("📝 Or paste text for inspection"):
        manual_text = st.text_area(
            "Paste document text here",
            height=200,
            placeholder="Paste your document content here for CUI inspection..."
        )
        manual_filename = st.text_input("Document name", "manual_input.txt")
    
    if st.button("🔍 Inspect for CUI", type="primary"):
        all_findings = []
        
        # Process uploaded files
        if uploaded_files:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for idx, uploaded_file in enumerate(uploaded_files):
                status_text.text(f"Processing {uploaded_file.name}...")
                try:
                    # Use the new inspect_file method that handles different file types
                    findings = inspector.inspect_file(uploaded_file, uploaded_file.name)
                    all_findings.append(findings)
                except Exception as e:
                    st.error(f"Error processing {uploaded_file.name}: {str(e)}")
                    all_findings.append({
                        'filename': uploaded_file.name,
                        'timestamp': datetime.now().isoformat(),
                        'cui_detected': False,
                        'error': str(e),
                        'cui_categories': [],
                        'patterns_found': {},
                        'risk_level': 'ERROR',
                        'recommendations': [f"❌ Error processing file: {str(e)}"]
                    })
                
                progress_bar.progress((idx + 1) / len(uploaded_files))
            
            status_text.empty()
            progress_bar.empty()
        
        # Process manual input
        if manual_text:
            findings = inspector.inspect_text(manual_text, manual_filename)
            all_findings.append(findings)
        
        # Display results
        if all_findings:
            st.success(f"✅ Inspected {len(all_findings)} document(s)")
            
            for finding in all_findings:
                # Check if there was an error
                has_error = 'error' in finding and finding['risk_level'] == 'ERROR'
                
                with st.expander(f"📄 {finding['filename']}", expanded=True):
                    if has_error:
                        st.error(f"⚠️ Error processing this file: {finding.get('error', 'Unknown error')}")
                        continue
                    
                    # Risk level indicator
                    risk_colors = {
                        'LOW': '🟢',
                        'MEDIUM': '🟡',
                        'HIGH': '🔴'
                    }
                    risk_indicator = risk_colors.get(finding['risk_level'], '⚪')
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("CUI Detected", "Yes" if finding['cui_detected'] else "No")
                    with col2:
                        st.metric("Risk Level", f"{risk_indicator} {finding['risk_level']}")
                    with col3:
                        st.metric("Patterns Found", sum(finding['patterns_found'].values()))
                    
                    # Detected patterns
                    if finding['patterns_found']:
                        st.subheader("🔍 Detected Patterns")
                        pattern_df = pd.DataFrame([
                            {'Pattern Type': k, 'Occurrences': v}
                            for k, v in finding['patterns_found'].items()
                        ])
                        st.dataframe(pattern_df, use_container_width=True)
                    
                    # CUI categories
                    if finding['cui_categories']:
                        st.subheader("📋 CUI Categories Identified")
                        for category in set(finding['cui_categories']):
                            st.markdown(f"- {category}")
                    
                    # Recommendations
                    st.subheader("💡 CMMC Compliance Recommendations")
                    for rec in finding['recommendations']:
                        st.markdown(f"- {rec}")
                    
                    # Export individual finding
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        finding_json = json.dumps(finding, indent=2)
                        st.download_button(
                            label="📥 Download JSON Report",
                            data=finding_json,
                            file_name=f"cui_finding_{finding['filename']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json",
                            key=f"json_{finding['filename']}"
                        )
                    
                    with col2:
                        # Generate PDF report
                        try:
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_pdf:
                                inspector.generate_cui_report_pdf(finding, tmp_pdf.name)
                                tmp_pdf.seek(0)
                                
                                with open(tmp_pdf.name, 'rb') as pdf_file:
                                    pdf_data = pdf_file.read()
                                
                                st.download_button(
                                    label="📥 Download PDF Report",
                                    data=pdf_data,
                                    file_name=f"cui_report_{finding['filename']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                    mime="application/pdf",
                                    key=f"pdf_{finding['filename']}"
                                )
                                
                                # Clean up temp file
                                if os.path.exists(tmp_pdf.name):
                                    os.unlink(tmp_pdf.name)
                        except Exception as e:
                            st.error(f"Could not generate PDF report: {str(e)}")
        else:
            st.warning("⚠️ No documents to inspect. Please upload files or paste text.")


def render_data_flow_mapper():
    """Render data flow mapping interface"""
    st.header("🗺️ CMMC Data Flow Mapper")
    st.info("""
    **Purpose:** Document data flows for System Security Plan (SSP) compliance per CMMC Level 2 requirements.
    **Documentation:** Essential for demonstrating CUI protection throughout its lifecycle.
    """)
    
    # Initialize session state for data flows
    if 'data_flows' not in st.session_state:
        st.session_state.data_flows = DataFlowMapper()
    
    mapper = st.session_state.data_flows
    
    st.subheader("➕ Add New Data Flow")
    
    col1, col2 = st.columns(2)
    
    with col1:
        source = st.text_input("Source System/Component",
                              placeholder="e.g., Engineering Workstation, AWS S3 Bucket")
        destination = st.text_input("Destination System/Component",
                                   placeholder="e.g., SharePoint, Contractor Portal")
        data_type = st.text_input("Data Type/Description",
                                 placeholder="e.g., Engineering Drawings, Contract Data")
    
    with col2:
        cui_present = st.checkbox("Contains CUI", value=False)
        encryption = st.selectbox(
            "Encryption Method",
            ["None", "TLS 1.2+", "TLS 1.3", "AES-256", "IPSec", "Other"]
        )
        controls = st.multiselect(
            "Security Controls Applied",
            [
                "AC.1.001 - Access Control",
                "AC.3.018 - Encryption at Rest",
                "AU.2.041 - Audit Logging",
                "IA.1.076 - Authentication",
                "SC.3.177 - Encryption in Transit",
                "SC.3.191 - Network Segmentation",
                "SI.1.210 - Malware Protection"
            ]
        )
    
    if st.button("➕ Add Data Flow"):
        if source and destination and data_type:
            flow = mapper.add_flow(source, destination, data_type,
                                  cui_present, encryption, controls)
            st.success(f"✅ Data flow #{flow['id']} added successfully!")
            st.rerun()
        else:
            st.error("❌ Please fill in Source, Destination, and Data Type")
    
    # Display existing flows
    if mapper.flows:
        st.subheader("📋 Documented Data Flows")
        
        # Create DataFrame
        flows_df = pd.DataFrame([
            {
                'ID': f['id'],
                'Source': f['source'],
                'Destination': f['destination'],
                'Data Type': f['data_type'],
                'CUI': '🔒 Yes' if f['cui_present'] else 'No',
                'Encryption': f['encryption'],
                'CMMC Level': f['cmmc_level'],
                'Controls': len(f['controls'])
            }
            for f in mapper.flows
        ])
        st.dataframe(flows_df, use_container_width=True)
        
        # Visualize data flow diagram
        st.subheader("🗺️ Data Flow Diagram")
        mermaid_code = mapper.generate_mermaid_diagram()
        st.markdown("""
```mermaid
""" + mermaid_code + """
```
""")
        st.caption("🔒 Red nodes indicate CUI data flows requiring enhanced protection")
        
        # Statistics
        st.subheader("📊 Data Flow Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Flows", len(mapper.flows))
        with col2:
            cui_flows = sum(1 for f in mapper.flows if f['cui_present'])
            st.metric("CUI Flows", cui_flows)
        with col3:
            encrypted = sum(1 for f in mapper.flows if f['encryption'] != "None")
            st.metric("Encrypted Flows", encrypted)
        with col4:
            level2_required = sum(1 for f in mapper.flows if "Level 2" in f['cmmc_level'])
            st.metric("CMMC Level 2 Required", level2_required)
        
        # Export options
        st.subheader("💾 Export Data Flow Documentation")
        col1, col2 = st.columns(2)
        
        with col1:
            json_export = mapper.export_to_json()
            st.download_button(
                label="📥 Download as JSON",
                data=json_export,
                file_name=f"data_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        with col2:
            csv_export = flows_df.to_csv(index=False)
            st.download_button(
                label="📥 Download as CSV",
                data=csv_export,
                file_name=f"data_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        # Clear all flows
        if st.button("🗑️ Clear All Flows", type="secondary"):
            st.session_state.data_flows = DataFlowMapper()
            st.rerun()


def render_cmmc_guidance():
    """Render CMMC guidance and requirements"""
    st.header("📚 CMMC 2.0 Guidance")
    
    tab1, tab2, tab3 = st.tabs(["CUI Requirements", "Data Flow Requirements", "AWS FedRAMP"])
    
    with tab1:
        st.markdown("""
        ### CUI Handling Requirements (NIST SP 800-171)
        
        #### 📋 CUI Identification
        - **Requirement:** All CUI must be identified and marked appropriately
        - **Standard:** 32 CFR Part 2002 - CUI Marking
        - **CMMC Practice:** AC.1.001, AC.1.002
        
        #### 🔐 Protection Requirements
        
        1. **Access Control (AC)**
           - AC.1.001: Limit access to authorized users
           - AC.3.018: Encrypt CUI at rest
        
        2. **Audit and Accountability (AU)**
           - AU.2.041: Ensure audit records are created and retained
        
        3. **System and Communications Protection (SC)**
           - SC.3.177: Employ FIPS-validated cryptography
           - SC.3.191: Separate user and privileged functions
        
        4. **Identification and Authentication (IA)**
           - IA.1.076: Identify users, processes, and devices
           - IA.2.078: Enforce minimum password complexity
        
        #### 📊 Risk Assessment
        - Documents containing CUI require enhanced security controls
        - Minimum CMMC Level 2 certification required for CUI
        """)
    
    with tab2:
        st.markdown("""
        ### Data Flow Documentation Requirements
        
        #### 🗺️ System Security Plan (SSP) Requirements
        - **CMMC Requirement:** Documented data flows showing CUI movement
        - **Purpose:** Demonstrate understanding of information systems and data paths
        - **Components Required:**
          1. Source and destination of all data flows
          2. Type of data being transmitted
          3. CUI designation (if applicable)
          4. Encryption methods employed
          5. Security controls protecting each flow
        
        #### ✅ Compliance Checklist
        - [ ] All CUI flows identified
        - [ ] Encryption documented for CUI in transit
        - [ ] Encryption documented for CUI at rest
        - [ ] Access controls documented
        - [ ] Audit logging enabled for CUI access
        - [ ] Network segmentation implemented
        - [ ] Data flow diagram included in SSP
        
        #### 📝 Assessment Objectives
        - Demonstrate CUI is protected throughout its lifecycle
        - Show proper technical safeguarding measures
        - Document compensating controls where applicable
        """)
    
    with tab3:
        st.markdown("""
        ### AWS FedRAMP Compliance
        
        #### ☁️ AWS GovCloud Considerations
        - **FedRAMP Authorization:** AWS GovCloud is FedRAMP High authorized
        - **CUI Storage:** Approved for CUI and sensitive government data
        - **Compliance:** Meets CMMC Level 2 technical requirements
        
        #### 🔒 Recommended AWS Services for CUI
        
        1. **Storage:**
           - Amazon S3 (with server-side encryption)
           - Amazon EBS (encrypted volumes)
        
        2. **Compute:**
           - Amazon EC2 (in GovCloud)
           - AWS Lambda (for serverless processing)
        
        3. **Database:**
           - Amazon RDS (encrypted instances)
           - Amazon DynamoDB (encryption at rest)
        
        4. **Security:**
           - AWS KMS (FIPS 140-2 validated encryption)
           - AWS CloudTrail (audit logging)
           - AWS IAM (access control)
           - AWS Security Hub (compliance monitoring)
        
        #### 🛡️ Shared Responsibility Model
        - **AWS Responsibility:** Physical security, infrastructure security
        - **Customer Responsibility:** Data encryption, access control, application security
        
        #### 📋 Required Configurations
        - Enable encryption at rest for all storage
        - Use TLS 1.2+ for all data in transit
        - Enable CloudTrail logging
        - Implement VPC network isolation
        - Use AWS Config for compliance monitoring
        - Enable GuardDuty for threat detection
        """)


# -----------------------------
# Evidence Vault: SQLite DB + Repo (content-addressed) + Versioned uploads
# -----------------------------
APP_VERSION = "cui-portal-1.0"
INSPECTOR_VERSION = "cui-inspector-1.0"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPO_DIR = DATA_DIR / "repo"
DB_PATH = DATA_DIR / "evidence_mt.db"

def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (REPO_DIR / "objects").mkdir(parents=True, exist_ok=True)
    (REPO_DIR / "refs").mkdir(parents=True, exist_ok=True)

def _db():
    _ensure_dirs()
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    return con

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tenants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  logical_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, logical_name),
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifact_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  artifact_id INTEGER NOT NULL,
  version_int INTEGER NOT NULL,
  original_filename TEXT NOT NULL,
  object_relpath TEXT NOT NULL,
  ref_relpath TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  mime TEXT,
  created_at TEXT NOT NULL,
  uploaded_by TEXT,
  UNIQUE(artifact_id, version_int),
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS inspections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  artifact_version_id INTEGER,
  run_type TEXT NOT NULL,               -- single|bulk|qa|training|verify|export
  app_version TEXT NOT NULL,
  inspector_version TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  cui_detected INTEGER,
  risk_level TEXT,
  patterns_json TEXT,
  categories_json TEXT,
  summary_json TEXT,
  error TEXT,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(artifact_version_id) REFERENCES artifact_versions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  inspection_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  object_relpath TEXT NOT NULL,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(inspection_id) REFERENCES inspections(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER,                    -- NULL for superadmin/auditor (cross-tenant)
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer',   -- superadmin|tenant_admin|auditor|analyst|viewer
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_login_at TEXT,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER,
  user_id INTEGER,
  event_type TEXT NOT NULL,
  details_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);

CREATE TABLE IF NOT EXISTS inspection_text_index (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  inspection_id INTEGER NOT NULL,
  artifact_version_id INTEGER,
  filename TEXT,
  file_ext TEXT,
  safe_excerpt TEXT,
  char_count INTEGER,
  word_count INTEGER,
  patterns_total INTEGER,
  categories_json TEXT,
  risk_level TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(inspection_id) REFERENCES inspections(id) ON DELETE CASCADE,
  FOREIGN KEY(artifact_version_id) REFERENCES artifact_versions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_text_index_risk ON inspection_text_index(risk_level);
CREATE INDEX IF NOT EXISTS idx_text_index_filename ON inspection_text_index(filename);

CREATE INDEX IF NOT EXISTS idx_inspections_started_at ON inspections(started_at);
CREATE INDEX IF NOT EXISTS idx_artifact_versions_sha256 ON artifact_versions(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_files_sha256 ON evidence_files(sha256);

"""

def init_evidence_store():
    con = _db()
    try:
        con.executescript(SCHEMA_SQL)
        con.commit()
    finally:
        con.close()

def normalize_logical_name(filename: str) -> str:
    # stable logical grouping (strip dirs, collapse whitespace, lower)
    base = os.path.basename(filename or "document")
    return re.sub(r"\s+", " ", base).strip().lower()

def _object_path_for_hash(sha256: str) -> Path:
    return REPO_DIR / "objects" / sha256[:2] / sha256

def repo_store_object(data: bytes) -> str:
    """
    Store bytes in content-addressed object store if not present.
    Returns relative path from REPO_DIR.
    """
    _ensure_dirs()
    sha = _sha256_bytes(data)
    obj_path = _object_path_for_hash(sha)
    obj_path.parent.mkdir(parents=True, exist_ok=True)
    if not obj_path.exists():
        with open(obj_path, "wb") as f:
            f.write(data)
    rel = obj_path.relative_to(REPO_DIR).as_posix()
    return rel

def repo_write_ref(artifact_id: int, version_int: int, original_filename: str, data: bytes) -> str:
    """
    Write a human-friendly versioned copy under repo/refs for browsing.
    Returns relative path from REPO_DIR.
    """
    _ensure_dirs()
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", os.path.basename(original_filename))
    ref_dir = REPO_DIR / "refs" / f"artifact_{artifact_id}" / f"v{version_int:04d}"
    ref_dir.mkdir(parents=True, exist_ok=True)
    ref_path = ref_dir / safe_name
    # Overwrite is fine; version folder is immutable by policy but file write is idempotent
    with open(ref_path, "wb") as f:
        f.write(data)
    return ref_path.relative_to(REPO_DIR).as_posix()

def upsert_artifact_and_version(tenant_id: int, filename: str, data: bytes, mime: str = None, uploaded_by: str = None) -> int:
    """
    Create/lookup artifact by logical name; add a new version if content differs from latest.
    Returns artifact_version_id.
    """
    init_evidence_store()
    logical = normalize_logical_name(filename)
    sha = _sha256_bytes(data)
    size = len(data)

    con = _db()
    try:
        cur = con.cursor()
        # ensure artifact row
        cur.execute("SELECT id FROM artifacts WHERE tenant_id = ? AND logical_name = ?", (tenant_id, logical))
        row = cur.fetchone()
        if row:
            artifact_id = int(row["id"])
        else:
            cur.execute("INSERT INTO artifacts (tenant_id, logical_name, created_at) VALUES (?, ?, ?)", (tenant_id, logical, _now_iso()))
            artifact_id = cur.lastrowid

        # check latest version hash
        cur.execute("""
            SELECT id, version_int, sha256 FROM artifact_versions
            WHERE tenant_id = ? AND artifact_id = ?
            ORDER BY version_int DESC
            LIMIT 1
        """, (tenant_id, artifact_id,))
        last = cur.fetchone()
        if last and last["sha256"] == sha:
            return int(last["id"])  # no new version

        next_ver = 1 if not last else int(last["version_int"]) + 1

        obj_rel = repo_store_object(data)
        ref_rel = repo_write_ref(artifact_id, next_ver, filename, data)

        cur.execute("""
            INSERT INTO artifact_versions
            (tenant_id, artifact_id, version_int, original_filename, object_relpath, ref_relpath, sha256, size_bytes, mime, created_at, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (tenant_id, artifact_id, next_ver, os.path.basename(filename), obj_rel, ref_rel, sha, size, mime, _now_iso(), uploaded_by))
        av_id = cur.lastrowid
        con.commit()
        return int(av_id)
    finally:
        con.close()

def save_inspection(artifact_version_id: int, run_type: str, findings: Dict, started_at: str, finished_at: str) -> int:
    """
    Persist inspection summary (not the full raw text) into SQLite.
    Returns inspection_id.
    """
    init_evidence_store()
    con = _db()
    try:
        cur = con.cursor()
        cur.execute("""
            INSERT INTO inspections
            (tenant_id, artifact_version_id, run_type, app_version, inspector_version, started_at, finished_at,
             cui_detected, risk_level, patterns_json, categories_json, summary_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tenant_id,
            artifact_version_id,
            run_type,
            APP_VERSION,
            INSPECTOR_VERSION,
            started_at,
            finished_at,
            1 if findings.get("cui_detected") else 0 if findings.get("cui_detected") is not None else None,
            findings.get("risk_level"),
            json.dumps(findings.get("patterns_found", {})),
            json.dumps(findings.get("cui_categories", [])),
            json.dumps({
                "filename": findings.get("filename"),
                "risk_score": findings.get("risk_score"),
                "summary": findings.get("summary"),
                "recommendations_count": len(findings.get("recommendations", []) or []),
            }),
            findings.get("error")
        ))
        ins_id = cur.lastrowid
        con.commit()
        return int(ins_id)
    finally:
        con.close()

def attach_evidence_file(tenant_id: int, inspection_id: int, kind: str, filename: str, data: bytes) -> int:
    """
    Store evidence output bytes into repo objects + record in db.
    """
    init_evidence_store()
    obj_rel = repo_store_object(data)
    sha = _sha256_bytes(data)
    size = len(data)
    con = _db()
    try:
        cur = con.cursor()
        cur.execute("""
            INSERT INTO evidence_files
            (tenant_id, inspection_id, kind, object_relpath, filename, sha256, size_bytes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (tenant_id, inspection_id, kind, obj_rel, os.path.basename(filename), sha, size, _now_iso()))
        eid = cur.lastrowid
        con.commit()
        return int(eid)
    finally:
        con.close()

def repo_read_object(relpath: str) -> bytes:
    p = REPO_DIR / relpath
    with open(p, "rb") as f:
        return f.read()

def list_recent_inspections(limit: int = 50):
    init_evidence_store()
    con = _db()
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT i.id, i.run_type, i.started_at, i.finished_at, i.cui_detected, i.risk_level,
                   av.original_filename, av.version_int, a.logical_name
            FROM inspections i
            LEFT JOIN artifact_versions av ON i.artifact_version_id = av.id
            LEFT JOIN artifacts a ON av.artifact_id = a.id
            WHERE i.tenant_id = ?
            ORDER BY i.started_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        con.close()

def list_evidence_files_for_inspection(inspection_id: int):
    init_evidence_store()
    con = _db()
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT id, kind, filename, object_relpath, sha256, size_bytes, created_at
            FROM evidence_files
            WHERE tenant_id = ? AND inspection_id = ?
            ORDER BY created_at DESC
        """, (_current_tenant_id(), inspection_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        con.close()

def render_evidence_vault():
    st.header("🗄️ Evidence Vault (SQLite + Repo + Versioning)")
    st.caption("Every upload and inspection run is stored with hashes + timestamps. Use this page to browse, export, and retrieve evidence.")
    init_evidence_store()

    # quick stats
    con = _db()
    try:
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) AS n FROM artifacts")
        a_n = int(cur.fetchone()["n"])
        cur.execute("SELECT COUNT(*) AS n FROM artifact_versions")
        v_n = int(cur.fetchone()["n"])
        cur.execute("SELECT COUNT(*) AS n FROM inspections")
        i_n = int(cur.fetchone()["n"])
        cur.execute("SELECT COUNT(*) AS n FROM evidence_files")
        e_n = int(cur.fetchone()["n"])
    finally:
        con.close()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Artifacts", a_n)
    c2.metric("Versions", v_n)
    c3.metric("Inspections", i_n)
    c4.metric("Evidence Files", e_n)

    st.divider()
    st.subheader("Recent inspections")
    rows = list_recent_inspections(limit=100)
    if not rows:
        st.info("No inspections have been saved yet. Run the inspector or bulk runner to populate the vault.")
        return

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)

    sel = st.selectbox("Select an inspection_id to view evidence files", options=[r["id"] for r in rows])
    files = list_evidence_files_for_inspection(sel)
    if files:
        fdf = pd.DataFrame(files)
        st.dataframe(fdf, use_container_width=True)

        st.subheader("Download evidence files")
        for f in files:
            data = repo_read_object(f["object_relpath"])
            st.download_button(
                f'⬇️ {f["kind"]}: {f["filename"]} (sha256 {f["sha256"][:10]}...)',
                data=data,
                file_name=f["filename"],
                mime="application/octet-stream"
            )
    else:
        st.warning("No evidence files attached to this inspection yet.")


# -----------------------------
# Add-ons: Test Bundle + QA + Training + Mapping
# -----------------------------

BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "CUI_Full_Test_Bundle.zip")
SAMPLE_DOCS = {
    "CUI_Mismarked.docx": "CUI_Mismarked.docx",
    "Mixed_CUI_NonCUI.docx": "Mixed_CUI_NonCUI.docx",
    "CUI_Handling_SOP.docx": "CUI_Handling_SOP.docx",
    "CUI_CMMC_L2_Mapping.xlsx": "CUI_CMMC_L2_Mapping.xlsx",
    "CUI_Training_Slides.pdf": "CUI_Training_Slides.pdf",
}

def _local_sample_path(filename: str) -> str:
    return os.path.join(os.path.dirname(__file__), filename)

def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def _zip_bytes(file_map: Dict[str, bytes]) -> bytes:
    """Return a zip as bytes from {name: data}"""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in file_map.items():
            z.writestr(name, data)
    buf.seek(0)
    return buf.read()

def _render_pdf_inline(pdf_bytes: bytes, height: int = 800):
    """Embed PDF in Streamlit via base64 iframe."""
    b64 = base64.b64encode(pdf_bytes).decode("utf-8")
    html = f"""
    <iframe src="data:application/pdf;base64,{b64}" width="100%" height="{height}" type="application/pdf"></iframe>
    """
    st.components.v1.html(html, height=height, scrolling=True)

def _generate_training_certificate_pdf(name: str, score: int, total: int) -> bytes:
    """Generate a simple completion certificate PDF."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from reportlab.lib import colors

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    w, h = letter

    # Border
    c.setStrokeColor(colors.HexColor("#1f77b4"))
    c.setLineWidth(3)
    c.rect(0.6*inch, 0.6*inch, w-1.2*inch, h-1.2*inch)

    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(w/2, h-1.5*inch, "Certificate of Completion")

    c.setFont("Helvetica", 12)
    c.drawCentredString(w/2, h-2.1*inch, "CUI Handling & Marking Training")

    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(w/2, h-3.0*inch, name.strip() if name.strip() else "Participant")

    c.setFont("Helvetica", 12)
    c.drawCentredString(w/2, h-3.6*inch, f"Score: {score}/{total}")

    c.setFont("Helvetica", 11)
    c.drawCentredString(w/2, h-4.2*inch, "This certificate acknowledges successful completion of the training module.")

    c.setFont("Helvetica-Oblique", 10)
    issued = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(0.9*inch, 0.9*inch, f"Issued: {issued}")
    c.drawRightString(w-0.9*inch, 0.9*inch, "Authorized Signature: ____________________")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()

def _mismarking_checks(text: str) -> Dict[str, any]:
    """
    Lightweight QA for potential CUI marking issues.
    Rules (heuristic):
      - If CUI indicators (PII/Export/Contract/etc) are found but no explicit CUI marking -> possible UNDER-marked.
      - If explicit CUI marking appears but no other indicators -> possible OVER-marked.
      - Look for mixture: 'CUI' + 'Public' or 'Unclassified' in same doc -> conflicting marking.
    """
    indicators = {}
    for k, pattern in CUI_PATTERNS.items():
        indicators[k] = len(re.findall(pattern, text, re.IGNORECASE))

    explicit = indicators.get("CUI_MARKING", 0) > 0
    substantive = sum(v for k, v in indicators.items() if k != "CUI_MARKING") > 0

    flags = []
    if substantive and not explicit:
        flags.append("Possible UNDER-marked: indicators found but no explicit CUI marking.")
    if explicit and not substantive:
        flags.append("Possible OVER-marked: explicit CUI marking present with few/no indicators detected.")
    if re.search(r"\b(PUBLIC|UNCLASSIFIED)\b", text, re.IGNORECASE) and explicit:
        flags.append("Conflicting marking: 'CUI' appears alongside PUBLIC/UNCLASSIFIED language.")

    return {
        "explicit_cui_marking": explicit,
        "indicator_counts": indicators,
        "flags": flags
    }

def render_test_bundle_runner():
    st.header("🧪 Test Bundle Runner")
    st.info("""
    **Purpose:** Quickly validate your CUI inspection + evidence workflows using a packaged test bundle.
    - Run bulk inspection against the included sample docs
    - Export consolidated CSV/JSON + per-file PDF reports
    - Download the full bundle for third‑party assessor testing
    """)

    # Bundle download
    if os.path.exists(BUNDLE_PATH):
        st.download_button(
            "⬇️ Download Full Test Bundle (ZIP)",
            data=_read_bytes(BUNDLE_PATH),
            file_name="CUI_Full_Test_Bundle.zip",
            mime="application/zip"
        )

    # Show sample docs downloads
    st.subheader("📦 Included sample artifacts")
    cols = st.columns(3)
    i = 0
    for label, filename in SAMPLE_DOCS.items():
        p = _local_sample_path(filename)
        if os.path.exists(p):
            with cols[i % 3]:
                st.download_button(
                    f"⬇️ {label}",
                    data=_read_bytes(p),
                    file_name=label,
                    mime="application/octet-stream"
                )
        i += 1

    st.divider()
    st.subheader("🚀 Run bulk inspection on included docs")
    inspector = CUIInspector()

    if st.button("Run on included docs", type="primary"):
        results = []
        pdf_reports = {}
        json_reports = {}

        for label, filename in SAMPLE_DOCS.items():
            p = _local_sample_path(filename)
            if not os.path.exists(p):
                continue
            # For PDFs/DOCX/XLSX we can open as bytes and pass BytesIO into inspector
            data = _read_bytes(p)
            bio = BytesIO(data)
            findings = inspector.inspect_file(bio, label)
            results.append(findings)
            json_reports[f"{label}.json"] = json.dumps(findings, indent=2).encode("utf-8")

            # PDF report (skip if error)
            if findings.get("risk_level") != "ERROR":
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
                        inspector.generate_cui_report_pdf(findings, tmp_pdf.name)
                        with open(tmp_pdf.name, "rb") as f:
                            pdf_reports[f"reports/{label}.pdf"] = f.read()
                    os.unlink(tmp_pdf.name)
                except Exception as e:
                    pass

        if results:
            st.success(f"Completed bulk run on {len(results)} artifact(s).")
            # Summary dataframe
            summary = []
            for r in results:
                summary.append({
                    "filename": r.get("filename"),
                    "cui_detected": r.get("cui_detected"),
                    "risk_level": r.get("risk_level"),
                    "patterns_total": sum(r.get("patterns_found", {}).values()),
                    "categories": "; ".join(sorted(set(r.get("cui_categories", [])))),
                    "error": r.get("error", "")
                })
            df = pd.DataFrame(summary)
            st.dataframe(df, use_container_width=True)

            # Downloads: consolidated CSV + zip of evidence
                        if st.session_state.get('autosave_bulk', True):
                # Save a bulk run inspection record (no single artifact_version_id)
                bulk_findings = {
                    'cui_detected': None,
                    'risk_level': 'BULK',
                    'patterns_found': {},
                    'cui_categories': [],
                    'risk_score': None,
                    'summary': f"Bulk run on {len(results)} artifacts",
                    'recommendations': [],
                }
                bulk_ins_id = save_inspection(_current_tenant_id(), None, run_type='bulk', findings=bulk_findings, started_at=_now_iso(), finished_at=_now_iso())
                attach_evidence_file(_current_tenant_id(), bulk_ins_id, 'summary_csv', 'bulk_summary.csv', df.to_csv(index=False).encode('utf-8'))
            
            st.download_button(
                "⬇️ Download Summary CSV",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name=f"cui_bulk_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

            bundle_zip = _zip_bytes({**json_reports, **pdf_reports})
            if st.session_state.get('autosave_bulk', True):
                try:
                    attach_evidence_file(_current_tenant_id(), bulk_ins_id, 'outputs_zip', 'bulk_outputs.zip', bundle_zip)
                except Exception:
                    pass

            st.download_button(
                "⬇️ Download Bulk Run Outputs (ZIP)",
                data=bundle_zip,
                file_name=f"cui_bulk_outputs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                mime="application/zip"
            )

def render_cui_marking_qa():
    st.header("📑 CUI Marking QA (Under/Over/Conflicting)")
    st.info("""
    **Purpose:** Spot likely marking mistakes in documents:
    - **Under‑marked:** indicators present without explicit CUI marking
    - **Over‑marked:** explicit CUI marking with no indicators
    - **Conflicting:** CUI appears alongside PUBLIC/UNCLASSIFIED wording

    This is heuristic QA intended for workflow testing.
    """)

    inspector = CUIInspector()
    uploaded = st.file_uploader(
        "Upload document(s) for marking QA",
        accept_multiple_files=True,
        type=['txt','csv','json','md','pdf','docx','doc','xlsx','xls','pptx','ppt']
    )

    if st.button("Run marking QA"):
        if not uploaded:
            st.warning("Upload at least one file.")
            return

        outputs = []
        for f in uploaded:
            # Extract text using inspector's extractor
            try:
                bio = BytesIO(f.read())
                # Need filename for filetype routing; reuse inspector internals
                text = inspector.extract_text_from_file(bio, f.name)
                qa = _mismarking_checks(text)
                outputs.append({
                    "filename": f.name,
                    "explicit_cui_marking": qa["explicit_cui_marking"],
                    "flags": " | ".join(qa["flags"]) if qa["flags"] else "",
                    **{k: v for k, v in qa["indicator_counts"].items()}
                })
            except Exception as e:
                outputs.append({"filename": f.name, "error": str(e)})

        df = pd.DataFrame(outputs)
        st.dataframe(df, use_container_width=True)

        st.download_button(
            "⬇️ Download QA Results (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"cui_marking_qa_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

def render_cmmc_mapping_explorer():
    st.header("🧩 CMMC Level 2 Mapping Explorer")
    st.info("""
    **Purpose:** Browse and filter the provided CUI ↔ CMMC L2 mapping sheet.
    Use this to trace findings/recommendations back to practices for evidence packaging.
    """)
    p = _local_sample_path("CUI_CMMC_L2_Mapping.xlsx")
    if not os.path.exists(p):
        st.error("Mapping file not found next to app.py")
        return

    wb = openpyxl.load_workbook(p)
    sheet = wb[wb.sheetnames[0]]
    rows = list(sheet.iter_rows(values_only=True))
    header = [str(h) if h is not None else "" for h in rows[0]]
    data = rows[1:]
    df = pd.DataFrame(data, columns=header)

    # Simple filter widgets (best-effort since column names can vary)
    st.caption("Tip: If your sheet uses different column names, the free-text search will still work.")
    q = st.text_input("Search (any column)", "")
    if q.strip():
        mask = df.apply(lambda row: row.astype(str).str.contains(q, case=False, na=False).any(), axis=1)
        df_view = df[mask].copy()
    else:
        df_view = df

    st.dataframe(df_view, use_container_width=True)

    st.download_button(
        "⬇️ Download Filtered Mapping (CSV)",
        data=df_view.to_csv(index=False).encode("utf-8"),
        file_name=f"cmmc_l2_mapping_filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )

    st.download_button(
        "⬇️ Download Original Mapping (XLSX)",
        data=_read_bytes(p),
        file_name="CUI_CMMC_L2_Mapping.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

def render_training_and_certificate():
    st.header("🎓 Training + Certificate")
    st.info("""
    **Purpose:** Provide auditor-friendly evidence of workforce training completion for CUI handling/marking.
    - View the training slides
    - Complete a short quiz
    - Generate a completion certificate PDF
    """)

    slides_path = _local_sample_path("CUI_Training_Slides.pdf")
    if os.path.exists(slides_path):
        st.subheader("📚 Training Slides")
        pdf_bytes = _read_bytes(slides_path)
        with st.expander("View slides inline", expanded=False):
            _render_pdf_inline(pdf_bytes, height=900)
        st.download_button("⬇️ Download Slides (PDF)", data=pdf_bytes, file_name="CUI_Training_Slides.pdf", mime="application/pdf")

    st.subheader("📝 Quick Quiz")
    name = st.text_input("Participant name (for certificate)", "")

    # Simple quiz (keep deterministic)
    questions = [
        ("CUI should be protected according to contract, law, and policy requirements.", ["True", "False"], 0),
        ("If a document contains CUI indicators but lacks any CUI marking, it may be:", ["Over-marked", "Under-marked", "Correctly marked"], 1),
        ("For CUI in transit, recommended minimum is:", ["TLS 1.2+", "HTTP", "Telnet"], 0),
        ("Audit logs are relevant evidence for which CMMC domain in this app’s recommendations?", ["AU", "PE", "MA"], 0),
        ("If 'CUI' and 'PUBLIC' appear together, that is best described as:", ["Conflicting marking", "Encryption issue", "Normal"], 0),
    ]

    answers = []
    for idx, (q, opts, correct) in enumerate(questions, 1):
        ans = st.radio(f"{idx}. {q}", opts, index=0, key=f"quiz_{idx}")
        answers.append((ans, opts[correct]))

    if st.button("Grade quiz & generate certificate", type="primary"):
        score = sum(1 for (a, c) in answers if a == c)
        total = len(questions)
        if score == total:
            st.success(f"✅ Passed! Score: {score}/{total}")
        else:
            st.warning(f"⚠️ Score: {score}/{total} (You can retry; certificate still available for workflow testing.)")

        cert = _generate_training_certificate_pdf(name or "Participant", score, total)
        st.download_button(
            "⬇️ Download Certificate (PDF)",
            data=cert,
            file_name=f"CUI_Training_Certificate_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf"
        )


def build_evidence_manifest_csv(tenant_id: int) -> tuple[bytes, bytes]:
    init_evidence_store()
    con = _db()
    try:
        rows = con.execute("""
            SELECT
              t.name AS tenant,
              a.logical_name,
              av.version_int,
              av.original_filename,
              av.sha256 AS artifact_sha256,
              av.size_bytes AS artifact_size_bytes,
              av.object_relpath AS artifact_object_relpath,
              av.ref_relpath AS artifact_ref_relpath,
              i.id AS inspection_id,
              i.run_type,
              i.started_at,
              i.finished_at,
              i.risk_level,
              ef.kind AS evidence_kind,
              ef.filename AS evidence_filename,
              ef.sha256 AS evidence_sha256,
              ef.size_bytes AS evidence_size_bytes,
              ef.object_relpath AS evidence_object_relpath,
              ef.created_at AS evidence_created_at
            FROM tenants t
            LEFT JOIN artifacts a ON a.tenant_id = t.id
            LEFT JOIN artifact_versions av ON av.artifact_id = a.id AND av.tenant_id = t.id
            LEFT JOIN inspections i ON i.tenant_id = t.id AND i.artifact_version_id = av.id
            LEFT JOIN evidence_files ef ON ef.tenant_id = t.id AND ef.inspection_id = i.id
            WHERE t.id = ?
            ORDER BY a.logical_name, av.version_int DESC, i.started_at DESC, ef.created_at DESC
        """, (tenant_id,)).fetchall()
        df = pd.DataFrame([dict(r) for r in rows])
    finally:
        con.close()

    csv_bytes = df.to_csv(index=False).encode("utf-8")
    hash_lines = []
    if not df.empty:
        for _, r in df.iterrows():
            if isinstance(r.get("artifact_sha256"), str) and r.get("artifact_object_relpath"):
                hash_lines.append(f'{r["artifact_sha256"]}  ARTIFACT  {r.get("original_filename","")}  {r["artifact_object_relpath"]}')
            if isinstance(r.get("evidence_sha256"), str) and r.get("evidence_object_relpath"):
                hash_lines.append(f'{r["evidence_sha256"]}  EVIDENCE:{r.get("evidence_kind","")}  {r.get("evidence_filename","")}  {r["evidence_object_relpath"]}')
    hash_txt = ("\n".join(hash_lines) + "\n").encode("utf-8")
    return csv_bytes, hash_txt

def render_evidence_manifest():
    st.header("📦 Evidence Export Manifest (FedRAMP / CMMC)")
    tenant_id = _current_tenant_id()
    if tenant_id is None:
        st.error("No tenant selected.")
        return

    include_objects = st.toggle("Include evidence objects in ZIP (can be large)", value=False)

    if st.button("Generate manifest", type="primary"):
        csv_bytes, hash_txt = build_evidence_manifest_csv(int(tenant_id))

        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.csv", csv_bytes)
            z.writestr("hashes.sha256.txt", hash_txt)
            if include_objects:
                con = _db()
                try:
                    rels = con.execute("""
                        SELECT DISTINCT object_relpath FROM artifact_versions WHERE tenant_id=?
                        UNION
                        SELECT DISTINCT object_relpath FROM evidence_files WHERE tenant_id=?
                    """, (tenant_id, tenant_id)).fetchall()
                finally:
                    con.close()
                for rr in rels:
                    rel = rr["object_relpath"]
                    try:
                        data = repo_read_object(rel)
                        z.writestr(f"objects/{rel}", data)
                    except Exception:
                        pass
        buf.seek(0)
        zip_bytes = buf.read()

        ins_id = save_inspection(int(tenant_id), None, run_type="export", findings={"risk_level":"EXPORT","patterns_found":{}, "cui_categories":[], "summary":"Evidence manifest export", "recommendations":[]}, started_at=_now_iso(), finished_at=_now_iso())
        attach_evidence_file(int(tenant_id), ins_id, "manifest_zip", "evidence_manifest.zip", zip_bytes)
        _audit("export_manifest", {"inspection_id": ins_id, "include_objects": include_objects})

        st.download_button("⬇️ Download manifest ZIP", data=zip_bytes, file_name=f"evidence_manifest_tenant_{tenant_id}.zip", mime="application/zip")



def _pbkdf2_hash(password: str, iters: int = 200_000) -> str:
    import hashlib, secrets
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iters)
    return f"pbkdf2_sha256${iters}${salt}${dk.hex()}"

def _pbkdf2_verify(password: str, stored: str) -> bool:
    import hashlib
    try:
        algo, iters_s, salt, hexhash = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iters)
        return dk.hex() == hexhash
    except Exception:
        return False


# -----------------------------
# Auth + Tenant Management UI
# -----------------------------
def render_login():
    st.header("🔐 Sign in")
    init_evidence_store()
    ensure_default_tenant()

    con = _db()
    try:
        user_count = int(con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])
    finally:
        con.close()

    if user_count == 0:
        st.warning("No users exist yet. Create the first SuperAdmin account to bootstrap access.")
        with st.form("bootstrap_superadmin"):
            username = st.text_input("SuperAdmin username", value="superadmin").strip().lower()
            password = st.text_input("SuperAdmin password", type="password")
            password2 = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Create SuperAdmin")
        if submitted:
            if not username or not password or password != password2:
                st.error("Please provide a username and matching passwords.")
                return
            con = _db()
            try:
                con.execute(
                    "INSERT INTO users (tenant_id, username, password_hash, role, is_active, created_at) VALUES (NULL, ?, ?, 'superadmin', 1, ?)",
                    (username, _pbkdf2_hash(password), _now_iso())
                )
                con.commit()
            finally:
                con.close()
            st.success("SuperAdmin created. Please sign in.")
            return

    with st.form("login_form"):
        username = st.text_input("Username").strip().lower()
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        con = _db()
        try:
            r = con.execute("SELECT id, tenant_id, username, password_hash, role, is_active FROM users WHERE username = ?", (username,)).fetchone()
            if not r or int(r["is_active"]) != 1 or not _pbkdf2_verify(password, r["password_hash"]):
                st.error("Invalid credentials.")
                return
            con.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (_now_iso(), int(r["id"])))
            con.commit()
            st.session_state["auth_user"] = {
                "id": int(r["id"]),
                "username": r["username"],
                "role": r["role"],
                "tenant_id": (int(r["tenant_id"]) if r["tenant_id"] is not None else None),
            }
            # Set tenant context
            if _has_cross_tenant_access():
                _set_current_tenant_id(ensure_default_tenant())
            else:
                _set_current_tenant_id(int(r["tenant_id"]) if r["tenant_id"] is not None else ensure_default_tenant())
            _audit("login_success", {"username": r["username"], "role": r["role"]})
            st.success("Signed in.")
            st.rerun()
        finally:
            con.close()

def render_logout_button():
    u = _current_user()
    if u:
        st.sidebar.markdown(f"**Signed in:** {u['username']} ({u['role']})")
        if st.sidebar.button("Sign out"):
            _audit("logout", {"username": u["username"]})
            st.session_state.pop("auth_user", None)
            st.session_state.pop("tenant_id", None)
            st.rerun()

def render_superadmin_tenants():
    st.header("🛡️ SuperAdmin – Tenant Management")
    if not _is_superadmin():
        st.error("SuperAdmins only.")
        return
    init_evidence_store()
    st.subheader("Create tenant")
    with st.form("create_tenant"):
        name = st.text_input("Tenant name (unique)").strip().lower()
        ok = st.form_submit_button("Create tenant")
    if ok:
        if not name:
            st.error("Tenant name required.")
        else:
            con = _db()
            try:
                con.execute("INSERT INTO tenants (name, created_at, is_active) VALUES (?, ?, 1)", (name, _now_iso()))
                con.commit()
            finally:
                con.close()
            _audit("tenant_create", {"name": name})
            st.success("Tenant created.")
            st.rerun()

    st.divider()
    st.subheader("Tenants")
    df = pd.DataFrame(list_tenants(active_only=False))
    st.dataframe(df, use_container_width=True)

def render_user_admin():
    st.header("👤 Tenant User Admin")
    if not (_is_superadmin() or _is_tenant_admin()):
        st.error("Tenant Admins or SuperAdmins only.")
        return
    init_evidence_store()
    st.caption("Tenant Admins manage users in their tenant. SuperAdmins can create cross-tenant Auditors (tenant_id=NULL).")

    st.subheader("Create user")
    with st.form("create_user"):
        username = st.text_input("Username").strip().lower()
        role_options = ["viewer", "analyst", "tenant_admin"] if not _is_superadmin() else ["viewer","analyst","tenant_admin","auditor"]
        role = st.selectbox("Role", role_options)
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Create")
    if submitted:
        if not username or not password:
            st.error("Username and password required.")
        else:
            tenant_id = _current_tenant_id()
            if role == "auditor" and _is_superadmin():
                tenant_id = None  # auditors can access any tenant
            con = _db()
            try:
                con.execute(
                    "INSERT INTO users (tenant_id, username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                    (tenant_id, username, _pbkdf2_hash(password), role, _now_iso())
                )
                con.commit()
            finally:
                con.close()
            _audit("user_create", {"username": username, "role": role, "tenant_id": tenant_id})
            st.success("User created.")
            st.rerun()

    st.divider()
    st.subheader("Users")
    con = _db()
    try:
        if _is_superadmin():
            rows = con.execute("""
                SELECT u.id, u.username, u.role, u.is_active, t.name AS tenant, u.created_at, u.last_login_at
                FROM users u LEFT JOIN tenants t ON t.id = u.tenant_id
                ORDER BY u.created_at DESC
            """).fetchall()
        else:
            rows = con.execute("""
                SELECT u.id, u.username, u.role, u.is_active, t.name AS tenant, u.created_at, u.last_login_at
                FROM users u LEFT JOIN tenants t ON t.id = u.tenant_id
                WHERE u.tenant_id = ?
                ORDER BY u.created_at DESC
            """, (_current_tenant_id(),)).fetchall()
        df = pd.DataFrame([dict(r) for r in rows])
    finally:
        con.close()
    st.dataframe(df, use_container_width=True)

    sel = st.selectbox("Select user_id", options=df["id"].tolist() if not df.empty else [])
    if sel:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Disable user"):
                con = _db()
                try:
                    con.execute("UPDATE users SET is_active = 0 WHERE id = ?", (int(sel),))
                    con.commit()
                finally:
                    con.close()
                _audit("user_disable", {"user_id": int(sel)})
                st.success("User disabled.")
                st.rerun()
        with col2:
            with st.form("reset_pw"):
                new_pw = st.text_input("New password", type="password")
                ok = st.form_submit_button("Reset password")
            if ok:
                if not new_pw:
                    st.error("Password required.")
                else:
                    con = _db()
                    try:
                        con.execute("UPDATE users SET password_hash = ? WHERE id = ?", (_pbkdf2_hash(new_pw), int(sel)))
                        con.commit()
                    finally:
                        con.close()
                    _audit("password_reset", {"user_id": int(sel)})
                    st.success("Password reset.")

def render_audit_log():
    st.header("🧾 Audit Log")
    init_evidence_store()
    limit = st.slider("Rows", 50, 500, 200, step=50)
    con = _db()
    try:
        if _has_cross_tenant_access():
            rows = con.execute("""
                SELECT ae.id, ae.created_at, ae.event_type, u.username, t.name AS tenant, ae.details_json
                FROM audit_events ae
                LEFT JOIN users u ON u.id = ae.user_id
                LEFT JOIN tenants t ON t.id = ae.tenant_id
                ORDER BY ae.created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
        else:
            rows = con.execute("""
                SELECT ae.id, ae.created_at, ae.event_type, u.username, ae.details_json
                FROM audit_events ae
                LEFT JOIN users u ON u.id = ae.user_id
                WHERE ae.tenant_id = ?
                ORDER BY ae.created_at DESC
                LIMIT ?
            """, (_current_tenant_id(), limit)).fetchall()
        df = pd.DataFrame([dict(r) for r in rows])
    finally:
        con.close()
    st.dataframe(df, use_container_width=True)
    st.download_button("⬇️ Download audit log CSV", data=df.to_csv(index=False).encode("utf-8"),
                       file_name=f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")



def main():
    """Main application function"""
    # Render header
    render_header()

    if not _require_login():
        render_login()
        return
    
    # Sidebar navigation
    with st.sidebar:
        st.image("https://via.placeholder.com/200x80/1f77b4/ffffff?text=CUI+Inspector",
                use_container_width=True)
        st.markdown("### 🧭 Navigation")
        page = st.radio(
            "Select Function",
            ["📄 CUI Document Inspector",
             "🗺️ Data Flow Mapper",
             "🧪 Test Bundle Runner",
             "📑 CUI Marking QA",
             "🧩 CMMC L2 Mapping Explorer",
             "🎓 Training + Certificate",
             "🗄️ Evidence Vault",
            "📦 Evidence Manifest",
            "👤 Tenant User Admin",
            "🛡️ SuperAdmin (Tenants)",
            "🧾 Audit Log",
             "📚 CMMC Guidance"],
            label_visibility="collapsed"
        )
        
        st.divider()
        
        st.markdown("### ℹ️ System Information")
        st.info("""
        **Version:** 1.0.0
        **Compliance:** CMMC 2.0
        **Framework:** NIST SP 800-171
        **Cloud:** AWS FedRAMP
        """)
        
        st.markdown("### 🔗 Quick Links")
        st.markdown("""
        - [CMMC 2.0 Model](https://dodcio.defense.gov/CMMC/)
        - [NIST SP 800-171](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
        - [CUI Registry](https://www.archives.gov/cui)
        - [AWS FedRAMP](https://aws.amazon.com/compliance/fedramp/)
        """)
    
    # Render selected page
    if page == "📄 CUI Document Inspector":
        render_cui_inspector()
    elif page == "🗺️ Data Flow Mapper":
        render_data_flow_mapper()
    elif page == "🧪 Test Bundle Runner":
        render_test_bundle_runner()
    elif page == "📑 CUI Marking QA":
        render_cui_marking_qa()
    elif page == "🧩 CMMC L2 Mapping Explorer":
        render_cmmc_mapping_explorer()
    elif page == "🎓 Training + Certificate":
        render_training_and_certificate()
    elif page == "🗄️ Evidence Vault",
            "📦 Evidence Manifest",
            "👤 Tenant User Admin",
            "🛡️ SuperAdmin (Tenants)",
            "🧾 Audit Log":
        render_evidence_vault()
    else:
        render_cmmc_guidance()
    
    # Footer
    st.divider()
    st.caption(f"""
    🔒 CUI Inspector & CMMC Data Flow Mapper | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    ⚠️ This tool assists with CMMC compliance documentation but does not replace professional assessment.
    Consult with a Certified CMMC Professional (CCP) for official certification.
    """)


if __name__ == "__main__":
    main()
