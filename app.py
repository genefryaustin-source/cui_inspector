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
import PyPDF2
from docx import Document
import openpyxl
from pptx import Presentation

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
        """Extract text from PDF file"""
        try:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text
        except Exception as e:
            raise Exception(f"Error extracting PDF text: {str(e)}")
    
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
                    finding_json = json.dumps(finding, indent=2)
                    st.download_button(
                        label="📥 Download Finding Report (JSON)",
                        data=finding_json,
                        file_name=f"cui_finding_{finding['filename']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
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


def main():
    """Main application function"""
    # Render header
    render_header()
    
    # Sidebar navigation
    with st.sidebar:
        st.image("https://via.placeholder.com/200x80/1f77b4/ffffff?text=CUI+Inspector",
                use_container_width=True)
        st.markdown("### 🧭 Navigation")
        page = st.radio(
            "Select Function",
            ["📄 CUI Document Inspector",
             "🗺️ Data Flow Mapper",
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
