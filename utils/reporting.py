# reporting.py
import json
from reportlab.lib.pagesizes import A4, letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    Image, ListFlowable, ListItem, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from io import BytesIO
from datetime import datetime
from utils.helpers import format_timestamp, categorize_subdomain
import os
import tempfile
from typing import Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()
        self.logo_path = self._get_logo_path()
        self.temp_dir = tempfile.mkdtemp()

    def _get_logo_path(self) -> Optional[str]:
        """Check for logo in common locations"""
        paths = [
            os.path.join('static', 'logo.png'),
            os.path.join('assets', 'logo.png'),
            'logo.png'
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def _setup_styles(self):
        """Setup retro report styles to match the web UI"""
        # Base colors
        self.primary_color = colors.HexColor('#4a6baf')
        self.secondary_color = colors.HexColor('#2c3e50')
        self.accent_color = colors.HexColor('#e74c3c')
        self.bg_color = colors.HexColor('#f0f0f0')
        self.text_color = colors.HexColor('#000000')
        self.border_color = colors.HexColor('#000000')
        
        # Risk level colors
        self.risk_colors = {
            'critical': colors.HexColor('#ff0000'),
            'high': colors.HexColor('#ff6600'),
            'medium': colors.HexColor('#0066ff'),
            'low': colors.HexColor('#00aa00'),
            'info': colors.HexColor('#666666')
        }

        # Title style
        self.title_style = ParagraphStyle(
            'Title',
            parent=self.styles['Title'],
            fontSize=24,
            leading=28,
            spaceAfter=12,
            alignment=TA_CENTER,
            textColor=self.text_color,
            fontName='Courier-Bold',
            borderWidth=2,
            borderColor=self.border_color,
            borderPadding=(5, 5, 5, 5),
            backColor=self.bg_color
        )

        # Heading styles
        self.heading1_style = ParagraphStyle(
            'Heading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            leading=22,
            spaceAfter=8,
            spaceBefore=16,
            textColor=self.text_color,
            fontName='Courier-Bold',
            underlineWidth=1,
            underlineColor=self.border_color,
            backColor=self.bg_color
        )

        self.heading2_style = ParagraphStyle(
            'Heading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            leading=18,
            spaceAfter=6,
            spaceBefore=12,
            textColor=self.text_color,
            fontName='Courier-Bold',
            backColor=self.bg_color
        )

        # Body styles
        self.body_style = ParagraphStyle(
            'Body',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=6,
            alignment=TA_LEFT,
            textColor=self.text_color,
            fontName='Courier',
            backColor=self.bg_color
        )

        self.bullet_style = ParagraphStyle(
            'Bullet',
            parent=self.body_style,
            leftIndent=10,
            spaceBefore=3,
            bulletIndent=5,
            bulletFontName='Courier',
            bulletFontSize=10
        )

        # Table styles
        self.table_header_style = ParagraphStyle(
            'TableHeader',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName='Courier-Bold',
            backColor=self.primary_color
        )

        self.table_cell_style = ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontSize=9,
            leading=11,
            textColor=self.text_color,
            alignment=TA_LEFT,
            fontName='Courier',
            backColor=self.bg_color
        )

        # Badge style
        self.badge_style = ParagraphStyle(
            'Badge',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName='Courier-Bold',
            borderWidth=1,
            borderColor=self.border_color,
            borderPadding=(2, 2, 2, 2),
            backColor=self.primary_color
        )

    def generate_pdf(self, scan_results: Dict) -> bytes:
        """Generate PDF report with retro styling"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
            title=f"Security Report - {scan_results.get('domain', 'Unknown')}",
            author="FoxRecon"
        )

        story = []
        
        # Add cover page with retro styling
        story.extend(self._create_retro_cover_page(scan_results))
        
        # Table of Contents
        story.extend(self._create_retro_toc())
        
        # Executive Summary
        story.extend(self._create_retro_executive_summary(scan_results))
        
        # Detailed Findings
        story.extend(self._create_retro_subdomain_analysis(scan_results))
        story.extend(self._create_retro_port_scan_results(scan_results))
        story.extend(self._create_retro_technology_detection(scan_results))
        story.extend(self._create_retro_email_enumeration(scan_results))
        
        # Security Analysis
        if 'security_analysis' in scan_results:
            story.extend(self._create_retro_security_analysis(scan_results['security_analysis']))
        
        # AI Analysis
        if 'ai_analysis' in scan_results:
            story.extend(self._create_retro_ai_analysis(scan_results['ai_analysis']))
        
        # Appendix
        story.extend(self._create_retro_appendix())

        doc.build(story)
        return buffer.getvalue()

    def _create_retro_cover_page(self, scan_results: Dict) -> List:
        """Create retro-styled cover page"""
        elements = []
        
        # Add title with border
        elements.append(Spacer(1, 1*inch))
        elements.append(Paragraph("FOXRECON SECURITY REPORT", self.title_style))
        elements.append(Spacer(1, 0.5*inch))
        
        # Domain information with retro styling
        elements.append(Paragraph(f"Target: {scan_results.get('domain', 'Unknown')}", 
                                ParagraphStyle(
                                    'Domain',
                                    parent=self.heading1_style,
                                    fontSize=16,
                                    alignment=TA_CENTER,
                                    textColor=self.text_color,
                                    backColor=self.bg_color,
                                    borderWidth=1,
                                    borderColor=self.border_color,
                                    borderPadding=(5, 5, 5, 5)
                                )))
        elements.append(Spacer(1, 0.3*inch))
        
        # Metadata table with retro styling
        scan_time = format_timestamp(scan_results.get('timestamp', '')) or "Unknown"
        info_data = [
            ["<b>Scan ID:</b>", scan_results.get('scan_id', 'N/A')],
            ["<b>Date:</b>", scan_time],
            ["<b>Subdomains:</b>", str(len(scan_results.get('subdomains', [])))],
            ["<b>Active:</b>", str(len([s for s in scan_results.get('subdomains', []) 
                                      if s.get('http_status') or s.get('https_status')]))],
            ["<b>Open Ports:</b>", str(sum(len(scan.get('ports', []))) 
                                    for scan in scan_results.get('port_scan', []))],
            ["<b>Technologies:</b>", str(sum(len(techs) for techs in scan_results.get('tech_detection', {}).values()))]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (0,-1), 'Courier-Bold'),
            ('FONTNAME', (1,0), (1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('LEADING', (0,0), (-1,-1), 14),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 1, self.border_color),
            ('BACKGROUND', (0,0), (-1,0), self.primary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BACKGROUND', (0,1), (-1,-1), self.bg_color),
            ('BOX', (0,0), (-1,-1), 2, self.border_color)
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 0.5*inch))
        
        # Confidential notice with retro styling
        elements.append(Paragraph("CONFIDENTIAL", ParagraphStyle(
            'Confidential',
            parent=self.title_style,
            fontSize=14,
            textColor=self.accent_color,
            spaceBefore=20,
            alignment=TA_CENTER
        )))
        
        elements.append(Paragraph("This report contains sensitive security information and is intended only for authorized recipients.", 
                                ParagraphStyle(
                                    'Notice',
                                    parent=self.body_style,
                                    alignment=TA_CENTER,
                                    borderWidth=1,
                                    borderColor=self.border_color,
                                    borderPadding=(5, 5, 5, 5),
                                    backColor=self.bg_color
                                )))
        
        elements.append(PageBreak())
        return elements

    def _create_retro_toc(self) -> List:
        """Create retro-styled table of contents"""
        elements = [
            Paragraph("Table of Contents", self.heading1_style),
            Spacer(1, 0.3*inch)
        ]
        
        # This would be dynamically generated based on actual content
        toc_items = [
            ("1. Executive Summary", 4),
            ("2. Subdomain Analysis", 5),
            ("3. Port Scan Results", 6),
            ("4. Technology Detection", 7),
            ("5. Email Enumeration", 8),
            ("6. Security Analysis", 9),
            ("7. AI Insights", 10),
            ("8. Appendix", 11)
        ]
        
        toc_data = []
        for item, page in toc_items:
            toc_data.append([item, str(page)])
        
        toc_table = Table(toc_data, colWidths=[4*inch, 1*inch])
        toc_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('LEADING', (0,0), (-1,-1), 14),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,0), (1,-1), 'RIGHT'),
            ('GRID', (0,0), (-1,-1), 1, self.border_color),
            ('BOX', (0,0), (-1,-1), 2, self.border_color),
            ('BACKGROUND', (0,0), (-1,-1), self.bg_color)
        ]))
        
        elements.append(toc_table)
        elements.append(PageBreak())
        return elements

    def _create_retro_executive_summary(self, scan_results: Dict) -> List:
        """Create retro-styled executive summary"""
        elements = [
            Paragraph("Executive Summary", self.heading1_style),
            Spacer(1, 0.2*inch)
        ]
    
        # Summary paragraph
        summary_text = f"""
        This security assessment report presents findings from a comprehensive reconnaissance and vulnerability analysis 
        of {scan_results['domain']}. The assessment employed automated scanning techniques to identify potential security 
        risks across the target infrastructure.
        """
        elements.append(Paragraph(summary_text, self.body_style))
        elements.append(Spacer(1, 0.3*inch))
    
        # Key findings table with retro styling
        findings_data = [
            ["<b>Category</b>", "<b>Findings</b>"],
            ["Subdomains Discovered", len(scan_results.get('subdomains', []))],
            ["Active Web Services", len([s for s in scan_results.get('subdomains', []) 
                                      if s.get('http_status') or s.get('https_status')])],
            ["Open Ports Identified", sum(len(scan.get('ports', [])) 
                                  for scan in scan_results.get('port_scan', []))],
            ["Unique Technologies", sum(len(techs) for techs in scan_results.get('tech_detection', {}).values())],
            ["Email Patterns Found", len(scan_results.get('email_enumeration', {}).get('email_formats', []))]
        ]
    
        findings_table = Table(findings_data, colWidths=[2.5*inch, 2.5*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), self.primary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
            ('FONTNAME', (0,1), (-1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 1, self.border_color),
            ('BOX', (0,0), (-1,-1), 2, self.border_color),
            ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
        ]))
    
        elements.append(findings_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Risk assessment with retro styling
        if 'security_analysis' in scan_results:
            risk = scan_results['security_analysis'].get('risk_assessment', {})
            elements.append(Paragraph("Risk Assessment", self.heading2_style))
            
            risk_level = risk.get('level', 'Unknown').lower()
            risk_color = self.risk_colors.get(risk_level, colors.black)
            
            risk_data = [
                ["<b>Risk Level:</b>", risk.get('level', 'Unknown')],
                ["<b>Risk Score:</b>", f"{risk.get('score', 0)}/100"],
                ["<b>Critical Findings:</b>", risk.get('critical_assets', 0)],
                ["<b>High Risk Findings:</b>", risk.get('total_risk_assets', 0) - risk.get('critical_assets', 0)]
            ]
            
            risk_table = Table(risk_data, colWidths=[2*inch, 3*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.accent_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (0,-1), 'Courier-Bold'),
                ('FONTNAME', (1,0), (1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color),
                ('TEXTCOLOR', (1,0), (1,0), risk_color)
            ]))
            
            elements.append(risk_table)
            elements.append(Spacer(1, 0.2*inch))
            
            # Risk factors with bullet points
            if risk.get('factors'):
                elements.append(Paragraph("Key Risk Factors:", self.heading2_style))
                risk_items = []
                for factor in risk['factors'][:5]:  # Limit to top 5 factors
                    risk_items.append(ListItem(Paragraph(factor, self.body_style), bulletColor='red'))
                
                elements.append(ListFlowable(risk_items, bulletType='bullet', start='square'))
        
        elements.append(PageBreak())
        return elements

    def _create_retro_subdomain_analysis(self, scan_results: Dict) -> List:
        """Create retro-styled subdomain analysis section"""
        elements = [
            Paragraph("Subdomain Analysis", self.heading1_style),
            Spacer(1, 0.2*inch)
        ]
        
        subdomains = scan_results.get('subdomains', [])
        active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
        
        # Statistics table with retro styling
        stats_data = [
            ["<b>Metric</b>", "<b>Count</b>"],
            ["Total Subdomains", len(subdomains)],
            ["Active Subdomains", len(active_subdomains)],
            ["HTTPS Enabled", len([s for s in active_subdomains if s.get('https_status')])],
            ["HTTP Only", len([s for s in active_subdomains 
                             if s.get('http_status') and not s.get('https_status')])],
            ["No Web Services", len([s for s in subdomains 
                                   if not s.get('http_status') and not s.get('https_status')])]
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5*inch, 2.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), self.primary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
            ('FONTNAME', (0,1), (-1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 1, self.border_color),
            ('BOX', (0,0), (-1,-1), 2, self.border_color),
            ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
        ]))
        
        elements.append(stats_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Active subdomains table with retro styling
        elements.append(Paragraph("Active Subdomains", self.heading2_style))
        
        active_data = [["<b>Subdomain</b>", "<b>IP</b>", "<b>HTTP</b>", "<b>HTTPS</b>", "<b>Title</b>"]]
        for sub in active_subdomains[:20]:  # Limit to 20 for readability
            active_data.append([
                sub['subdomain'],
                sub.get('ip', 'N/A'),
                sub.get('http_status', '-'),
                sub.get('https_status', '-'),
                sub.get('title', '')[:30] + ('...' if len(sub.get('title', '')) > 30 else '')
            ])
        
        active_table = Table(active_data, colWidths=[1.8*inch, 1.2*inch, 0.6*inch, 0.6*inch, 1.8*inch])
        active_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), self.secondary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
            ('FONTNAME', (0,1), (-1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 1, self.border_color),
            ('BOX', (0,0), (-1,-1), 2, self.border_color),
            ('BACKGROUND', (0,1), (-1,-1), self.bg_color),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
        ]))
        
        elements.append(active_table)
        elements.append(PageBreak())
        return elements

    def _create_retro_port_scan_results(self, scan_results: Dict) -> List:
        """Create retro-styled port scan results section"""
        if not scan_results.get('port_scan'):
            return []
            
        elements = [
            Paragraph("Port Scan Results", self.heading1_style),
            Spacer(1, 0.2*inch)
        ]
        
        total_open_ports = sum(len(scan.get('ports', [])) for scan in scan_results['port_scan'])
        elements.append(Paragraph(f"Total Open Ports Found: {total_open_ports}", self.heading2_style))
        elements.append(Spacer(1, 0.1*inch))
        
        # Port distribution chart with retro styling
        port_dist = {}
        for scan in scan_results['port_scan']:
            for port in scan.get('ports', []):
                service = port.get('service', 'unknown')
                port_dist[service] = port_dist.get(service, 0) + 1
        
        dist_data = [["<b>Service</b>", "<b>Count</b>"]]
        for service, count in sorted(port_dist.items(), key=lambda x: x[1], reverse=True)[:10]:  # Top 10
            dist_data.append([service, str(count)])
        
        dist_table = Table(dist_data, colWidths=[3*inch, 2*inch])
        dist_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), self.primary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
            ('FONTNAME', (0,1), (-1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 1, self.border_color),
            ('BOX', (0,0), (-1,-1), 2, self.border_color),
            ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
        ]))
        
        elements.append(dist_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Detailed port scan results with retro styling
        elements.append(Paragraph("Detailed Port Scan Results", self.heading2_style))
        
        for scan in scan_results['port_scan'][:5]:  # Limit to 5 targets for readability
            if not scan or not scan.get('ports'):
                continue
                
            elements.append(Paragraph(f"Target: {scan['target']}", self.heading2_style))
            
            port_data = [["<b>Port</b>", "<b>Service</b>", "<b>Version</b>", "<b>Risk</b>", "<b>Banner</b>"]]
            for port in scan['ports'][:20]:  # Limit to 20 ports per host
                banner = port.get('banner', '')
                risk_level = port.get('risk', {}).get('level', 'unknown').lower()
                risk_color = self.risk_colors.get(risk_level, colors.black)
                
                port_data.append([
                    str(port['port']),
                    port.get('service', 'unknown'),
                    port.get('version', ''),
                    port.get('risk', {}).get('level', 'unknown').title(),
                    banner[:50] + ('...' if len(banner) > 50 else '')
                ])
            
            port_table = Table(port_data, colWidths=[0.6*inch, 1.2*inch, 1*inch, 0.8*inch, 2.4*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.secondary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color),
                ('TEXTCOLOR', (3,1), (3,-1), risk_color)
            ]))
            
            elements.append(port_table)
            elements.append(Spacer(1, 0.2*inch))
        
        elements.append(PageBreak())
        return elements

    def _create_retro_technology_detection(self, scan_results: Dict) -> List:
        """Create retro-styled technology detection section"""
        if not scan_results.get('tech_detection'):
            return []
        
        elements = [
            Paragraph("Technology Detection", self.heading1_style),
            Spacer(1, 0.2*inch)
        ]
    
        # Technology summary with retro styling
        tech_summary = {}
        for url, techs in scan_results['tech_detection'].items():
            if isinstance(techs, str):
                elements.append(Paragraph(f"URL: {url}", self.heading2_style))
                elements.append(Paragraph("Technologies detected:", self.body_style))
                elements.append(Paragraph(techs, self.body_style))
                elements.append(Spacer(1, 0.2*inch))
                continue
            
            for tech in techs:
                if isinstance(tech, dict):
                    category = tech.get('category', 'other')
                    name = tech.get('name', 'unknown')
                else:
                    category = 'other'
                    name = str(tech)
                
                tech_summary[category] = tech_summary.get(category, {})
                tech_summary[category][name] = tech_summary[category].get(name, 0) + 1
    
        if tech_summary:
            summary_data = [["<b>Category</b>", "<b>Technologies</b>"]]
            for category, techs in tech_summary.items():
                tech_list = ", ".join([f"{name} ({count})" for name, count in techs.items()])
                summary_data.append([category.title(), tech_list])
        
            summary_table = Table(summary_data, colWidths=[1.5*inch, 3.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.primary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color),
                ('VALIGN', (0,0), (-1,-1), 'TOP')
            ]))
        
            elements.append(summary_table)
            elements.append(Spacer(1, 0.3*inch))
    
        # Detailed technology findings with retro styling
        elements.append(Paragraph("Detailed Technology Findings", self.heading2_style))
    
        for url, techs in scan_results['tech_detection'].items():
            if not techs:
                continue
            
            elements.append(Paragraph(f"URL: {url}", self.heading2_style))
        
            if isinstance(techs, str):
                elements.append(Paragraph(techs, self.body_style))
                elements.append(Spacer(1, 0.2*inch))
                continue
            
            tech_data = [["<b>Technology</b>", "<b>Version</b>", "<b>Category</b>", "<b>Confidence</b>"]]
            for tech in techs:
                if isinstance(tech, dict):
                    tech_data.append([
                        tech.get('name', 'N/A'),
                        tech.get('version', 'N/A'),
                        tech.get('category', 'N/A').title(),
                        f"{tech.get('confidence', 0)}%"
                    ])
                else:
                    tech_data.append([
                        str(tech),
                        'N/A',
                        'Other',
                        'N/A'
                    ])
        
            tech_table = Table(tech_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1*inch])
            tech_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.secondary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
            ]))
        
            elements.append(tech_table)
            elements.append(Spacer(1, 0.2*inch))
    
        elements.append(PageBreak())
        return elements

    def _create_retro_email_enumeration(self, scan_results: Dict) -> List:
        """Create retro-styled email enumeration section"""
        email_data = scan_results.get('email_enumeration', {})
        if not email_data:
            return []
            
        elements = [
            Paragraph("Email Enumeration", self.heading1_style),
            Spacer(1, 0.2*inch)
        ]
        
        # Email patterns with retro styling
        if email_data.get('email_formats'):
            elements.append(Paragraph("Discovered Email Patterns", self.heading2_style))
            
            pattern_data = [["<b>Pattern</b>", "<b>Example</b>", "<b>Confidence</b>"]]
            for pattern in email_data['email_formats']:
                pattern_data.append([
                    pattern.get('pattern', 'N/A'),
                    pattern.get('example', 'N/A'),
                    f"{pattern.get('confidence', 0)}%"
                ])
            
            pattern_table = Table(pattern_data, colWidths=[2*inch, 2*inch, 1*inch])
            pattern_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.primary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
            ]))
            
            elements.append(pattern_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Found emails with retro styling
        if email_data.get('found_emails'):
            elements.append(Paragraph("Discovered Emails", self.heading2_style))
            
            email_data = [["<b>Email</b>", "<b>Type</b>", "<b>Confidence</b>"]]
            for email in email_data['found_emails'][:20]:  # Limit to 20
                email_data.append([
                    email.get('email', 'N/A'),
                    email.get('type', 'N/A').title(),
                    f"{email.get('confidence', 0)}%"
                ])
            
            email_table = Table(email_data, colWidths=[2.5*inch, 1.5*inch, 1*inch])
            email_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.secondary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
            ]))
            
            elements.append(email_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Login pages with retro styling
        if email_data.get('login_pages'):
            elements.append(Paragraph("Discovered Login Pages", self.heading2_style))
            
            login_data = [["<b>URL</b>", "<b>Type</b>", "<b>Status</b>"]]
            for login in email_data['login_pages'][:10]:  # Limit to 10
                login_data.append([
                    login.get('url', 'N/A'),
                    login.get('type', 'N/A').title().replace('_', ' '),
                    login.get('status', '200')
                ])
            
            login_table = Table(login_data, colWidths=[3*inch, 1*inch, 1*inch])
            login_table.setStyle(TableStyle([
                                ('BACKGROUND', (0,0), (-1,0), self.accent_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
            ]))
            
            elements.append(login_table)
            elements.append(Spacer(1, 0.3*inch))
        
        elements.append(PageBreak())
        return elements

    def _create_retro_security_analysis(self, security_analysis: Dict) -> List:
        """Create retro-styled security analysis section"""
        if not security_analysis:
            return []
        
        elements = [
            Paragraph("Security Analysis", self.heading1_style),
            Spacer(1, 0.2*inch)
        ]
    
        # Risk assessment with retro styling
        risk = security_analysis.get('risk_assessment', {})
        elements.append(Paragraph("Risk Assessment", self.heading2_style))
    
        risk_level = risk.get('level', 'Unknown').lower()
        risk_color = self.risk_colors.get(risk_level, colors.black)

        risk_data = [
            ["<b>Risk Level:</b>", risk.get('level', 'Unknown')],
            ["<b>Risk Score:</b>", f"{risk.get('score', 0)}/100"],
            ["<b>Critical Findings:</b>", risk.get('critical_assets', 0)],
            ["<b>High Risk Findings:</b>", risk.get('total_risk_assets', 0) - risk.get('critical_assets', 0)]
            ]
    
        risk_table = Table(risk_data, colWidths=[2*inch, 3*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), self.accent_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (0,-1), 'Courier-Bold'),
            ('FONTNAME', (1,0), (1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 1, self.border_color),
            ('BOX', (0,0), (-1,-1), 2, self.border_color),
            ('BACKGROUND', (0,1), (-1,-1), self.bg_color),
            ('TEXTCOLOR', (1,0), (1,0), risk_color)
        ]))
    
        elements.append(risk_table)
        elements.append(Spacer(1, 0.2*inch))
    
        # Risk factors with bullet points
        if risk.get('factors'):
            elements.append(Paragraph("Key Risk Factors:", self.heading2_style))
            risk_items = []
            for factor in risk['factors'][:5]:  # Limit to top 5 factors
                risk_items.append(ListItem(Paragraph(factor, self.body_style), bulletColor='red'))
        
            elements.append(ListFlowable(risk_items, bulletType='bullet', start='square'))
            elements.append(Spacer(1, 0.2*inch))
    
        # Attack surface analysis with retro styling
        attack_surface = security_analysis.get('attack_surface', {})
        if attack_surface and attack_surface.get('vectors'):
            elements.append(Paragraph("Attack Surface Analysis", self.heading2_style))
        
            attack_data = [["<b>Vector Type</b>", "<b>Count</b>", "<b>Risk Level</b>"]]
            for vector in attack_surface['vectors'][:10]:  # Limit to 10
                risk_level = vector.get('risk', 'unknown').lower()
                attack_data.append([
                    vector.get('type', 'N/A'),
                    str(vector.get('count', 0)),
                    vector.get('risk', 'N/A').title()
                ])

            if len(attack_data) > 1:  # Ensure we have data rows
                table_style = [
                    ('BACKGROUND', (0,0), (-1,0), self.secondary_color),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                    ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                    ('FONTSIZE', (0,0), (-1,-1), 10),
                    ('GRID', (0,0), (-1,-1), 1, self.border_color),
                    ('BOX', (0,0), (-1,-1), 2, self.border_color),
                    ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
                ]
            
                # Only add TEXTCOLOR for risk level if we have data
                if len(attack_data) > 1:
                    table_style.append(('TEXTCOLOR', (2,1), (2,-1), self._get_risk_color(risk_level)))
                
                attack_table = Table(attack_data, colWidths=[2.5*inch, 1.5*inch, 1*inch])
                attack_table.setStyle(TableStyle(table_style))

                elements.append(attack_table)
                elements.append(Spacer(1, 0.2*inch))
    
        # High value targets with retro styling
        if security_analysis.get('high_value_targets'):
            elements.append(Paragraph("High Value Targets", self.heading2_style))
        
            target_data = [["<b>Subdomain</b>", "<b>Security Score</b>", "<b>Priority</b>"]]
            for target in security_analysis['high_value_targets'][:10]:  # Limit to 10
                target_data.append([
                    target.get('subdomain', 'N/A'),
                    str(target.get('security_score', 0)),
                    target.get('testing_priority', 'N/A')
                ])
        
            target_table = Table(target_data, colWidths=[2.5*inch, 1.5*inch, 1*inch])
            target_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.primary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
            ]))
        
            elements.append(target_table)
            elements.append(Spacer(1, 0.2*inch))

        # Recommendations with retro styling
        if security_analysis.get('recommendations'):
            elements.append(Paragraph("Security Recommendations", self.heading2_style))
        
            rec_data = [["<b>Priority</b>", "<b>Category</b>", "<b>Action</b>"]]
            for rec in security_analysis['recommendations'][:5]:  # Limit to 5
                rec_data.append([
                    rec.get('priority', 'N/A'),
                    rec.get('category', 'N/A'),
                    rec.get('action', 'N/A')[:100] + ('...' if len(rec.get('action', '')) > 100 else '')
                ])
        
            rec_table = Table(rec_data, colWidths=[1*inch, 1.5*inch, 2.5*inch])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.primary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
            ]))
        
            elements.append(rec_table)

        elements.append(PageBreak())
        return elements

    def _create_retro_ai_analysis(self, ai_analysis: Dict) -> List:
        """Create retro-styled AI analysis section"""
        if not ai_analysis:
            return []
            
        elements = [
            Paragraph("AI-Powered Security Insights", self.heading1_style),
            Spacer(1, 0.2*inch)
        ]
        
        # Owner perspective with retro styling
        owner = ai_analysis.get('owner_analysis', {})
        elements.append(Paragraph("Owner Perspective", self.heading2_style))
        
        if owner.get('summary'):
            elements.append(Paragraph("<b>Security Summary</b>", self.heading2_style))
            elements.append(Paragraph(owner['summary'], self.body_style))
            elements.append(Spacer(1, 0.1*inch))
        
        if owner.get('key_findings'):
            elements.append(Paragraph("<b>Key Findings:</b>", self.heading2_style))
            finding_items = []
            for finding in owner['key_findings'][:5]:  # Limit to 5
                finding_items.append(ListItem(Paragraph(finding, self.body_style), bulletColor='blue'))
            
            elements.append(ListFlowable(finding_items, bulletType='bullet', start='square'))
            elements.append(Spacer(1, 0.1*inch))
        
        if owner.get('protection_recommendations'):
            elements.append(Paragraph("<b>Protection Recommendations:</b>", self.heading2_style))
            rec_items = []
            for rec in owner['protection_recommendations'][:5]:  # Limit to 5
                rec_items.append(ListItem(Paragraph(rec, self.body_style), bulletColor='green'))
            
            elements.append(ListFlowable(rec_items, bulletType='bullet', start='square'))
            elements.append(Spacer(1, 0.1*inch))
        
        if owner.get('immediate_actions'):
            elements.append(Paragraph("<b>Immediate Actions:</b>", self.heading2_style))
            action_items = []
            for action in owner['immediate_actions'][:5]:  # Limit to 5
                action_items.append(ListItem(Paragraph(action, self.body_style), bulletColor='red'))
            
            elements.append(ListFlowable(action_items, bulletType='bullet', start='square'))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Hunter perspective with retro styling
        hunter = ai_analysis.get('hunter_analysis', {})
        elements.append(Paragraph("Bug Hunter Perspective", self.heading2_style))
        
        if hunter.get('summary'):
            elements.append(Paragraph("<b>Hunting Summary</b>", self.heading2_style))
            elements.append(Paragraph(hunter['summary'], self.body_style))
            elements.append(Spacer(1, 0.1*inch))
        
        if hunter.get('promising_targets'):
            elements.append(Paragraph("<b>Promising Targets:</b>", self.heading2_style))
            target_data = [["<b>Target</b>", "<b>Reason</b>"]]
            for target in hunter['promising_targets'][:5]:  # Limit to 5
                target_data.append([
                    target.get('target', 'N/A'),
                    target.get('reason', 'N/A')
                ])
            
            target_table = Table(target_data, colWidths=[2*inch, 3*inch])
            target_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.accent_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Courier-Bold'),
                ('FONTNAME', (0,1), (-1,-1), 'Courier'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('GRID', (0,0), (-1,-1), 1, self.border_color),
                ('BOX', (0,0), (-1,-1), 2, self.border_color),
                ('BACKGROUND', (0,1), (-1,-1), self.bg_color)
            ]))
            
            elements.append(target_table)
            elements.append(Spacer(1, 0.1*inch))
        
        if hunter.get('attack_vectors'):
            elements.append(Paragraph("<b>Attack Vectors:</b>", self.heading2_style))
            vector_items = []
            for vector in hunter['attack_vectors'][:5]:  # Limit to 5
                vector_items.append(ListItem(
                    Paragraph(f"<b>{vector.get('type', 'N/A')}:</b> {vector.get('description', 'N/A')}", 
                    self.body_style),
                    bulletColor='orange'
                ))
            
            elements.append(ListFlowable(vector_items, bulletType='bullet', start='square'))
            elements.append(Spacer(1, 0.1*inch))
        
        if hunter.get('high_value_findings'):
            elements.append(Paragraph("<b>High Value Findings:</b>", self.heading2_style))
            finding_items = []
            for finding in hunter['high_value_findings'][:5]:  # Limit to 5
                finding_items.append(ListItem(Paragraph(finding, self.body_style), bulletColor='red'))
            
            elements.append(ListFlowable(finding_items, bulletType='bullet', start='square'))
        
        elements.append(PageBreak())
        return elements

    def _create_retro_appendix(self) -> List:
        """Create retro-styled appendix section"""
        elements = [
            Paragraph("Appendix", self.heading1_style),
            Spacer(1, 0.2*inch),
            Paragraph("Methodology", self.heading2_style),
            Paragraph("This security assessment was conducted using the following automated techniques:", self.body_style),
            ListFlowable([
                ListItem(Paragraph("Subdomain enumeration through certificate transparency logs, DNS brute-forcing, and passive sources", self.body_style)),
                ListItem(Paragraph("Port scanning of common services (1-1000) with service detection", self.body_style)),
                ListItem(Paragraph("Technology fingerprinting through HTTP headers, HTML patterns, and JavaScript analysis", self.body_style)),
                ListItem(Paragraph("Email pattern detection through web scraping and common username enumeration", self.body_style)),
                ListItem(Paragraph("Rule-based security analysis identifying high-risk patterns and configurations", self.body_style)),
                ListItem(Paragraph("AI-powered insights providing contextual analysis and recommendations", self.body_style))
            ], bulletType='bullet'),
            Spacer(1, 0.2*inch),
            Paragraph("Disclaimer", self.heading2_style),
            Paragraph("This report is for authorized security assessment purposes only. Unauthorized scanning may violate laws and terms of service. The findings in this report represent potential security issues identified through automated scanning and should be validated through manual testing.", self.body_style),
            Spacer(1, 0.2*inch),
            Paragraph("Document Information", self.heading2_style),
            Paragraph(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.body_style),
            Paragraph("Tool: FoxRecon Security Assessment Toolkit", self.body_style),
            Paragraph("Version: 1.0", self.body_style)
        ]
        return elements

    def generate_json(self, scan_results: Dict) -> str:
        """Generate comprehensive JSON report"""
        report = {
            'metadata': {
                'domain': scan_results['domain'],
                'scan_id': scan_results.get('scan_id'),
                'timestamp': scan_results.get('timestamp'),
                'report_version': '1.0',
                'report_generated': datetime.now().isoformat()
            },
            'statistics': {
                'subdomains': len(scan_results.get('subdomains', [])),
                'active_subdomains': len([s for s in scan_results.get('subdomains', []) 
                                       if s.get('http_status') or s.get('https_status')]),
                'open_ports': sum(len(scan.get('ports', [])) 
                            for scan in scan_results.get('port_scan', [])),
                'technologies': sum(len(techs) 
                                  for techs in scan_results.get('tech_detection', {}).values()),
                'email_patterns': len(scan_results.get('email_enumeration', {}).get('email_formats', []))
            },
            'subdomains': scan_results.get('subdomains', []),
            'port_scan': scan_results.get('port_scan', []),
            'tech_detection': scan_results.get('tech_detection', {}),
            'email_enumeration': scan_results.get('email_enumeration', {}),
            'security_analysis': scan_results.get('security_analysis', {}),
            'ai_analysis': scan_results.get('ai_analysis', {})
        }
        
        return json.dumps(report, indent=2)

    def _get_risk_color(self, risk_level: str) -> colors.Color:
        """Get color for risk level"""
        return self.risk_colors.get(risk_level.lower(), colors.black)
