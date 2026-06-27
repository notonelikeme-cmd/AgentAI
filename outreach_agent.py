#!/usr/bin/env python3
"""
Outreach Agent Framework
Builds agents and tools for autonomous outreach operations.
"""

import json
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Any
from datetime import datetime
import subprocess

class OutreachTool(ABC):
    """Base class for outreach tools."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the tool and return results."""
        pass

class CompanyResearchTool(OutreachTool):
    """Tool to research a company and gather public information."""
    
    def __init__(self):
        super().__init__(
            'company_research',
            'Research a company online to gather public information about their web presence, technology stack, and security posture'
        )
    
    def execute(self, company_name: str, domain: str) -> Dict[str, Any]:
        """Research a company using Ollama."""
        prompt = f"""
        Research {company_name} ({domain}) and provide:
        1. Company description and what they do
        2. Website tech stack (frontend, backend, frameworks)
        3. Security-relevant observations (headers, HTTPS, exposed endpoints, admin panels)
        4. Estimated employee count and revenue tier
        5. Recent news or funding that indicates growth
        6. Likely decision-maker titles for security contact
        
        Format as JSON with keys: description, tech_stack, security_observations, size_estimate, growth_indicators, contact_titles
        Return ONLY JSON, no other text.
        """
        
        result = subprocess.run(
            ['ollama', 'run', 'qwen2.5-coder:14b'],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        try:
            data = json.loads(result.stdout.strip())
            return {'status': 'success', 'data': data}
        except json.JSONDecodeError:
            return {'status': 'error', 'message': result.stdout[:200]}

class VulnerabilityAssessmentTool(OutreachTool):
    """Tool to assess likely vulnerabilities for a company."""
    
    def __init__(self):
        super().__init__(
            'vulnerability_assessment',
            'Assess likely vulnerabilities in a company based on their tech stack and security posture'
        )
    
    def execute(self, company_name: str, tech_stack: str, security_posture: str) -> Dict[str, Any]:
        """Assess vulnerabilities using Ollama."""
        prompt = f"""
        Based on this company profile, identify likely web application vulnerabilities:
        
        Company: {company_name}
        Tech Stack: {tech_stack}
        Security Observations: {security_posture}
        
        Provide 5 likely vulnerability classes with:
        1. Vulnerability type
        2. Why it's likely given the tech stack
        3. Business impact
        4. Remediation approach
        
        Format as JSON array with objects: type, likelihood_reason, business_impact, remediation
        Return ONLY JSON, no other text.
        """
        
        result = subprocess.run(
            ['ollama', 'run', 'deepseek-r1:14b'],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        try:
            data = json.loads(result.stdout.strip())
            return {'status': 'success', 'vulnerabilities': data}
        except json.JSONDecodeError:
            return {'status': 'error', 'message': result.stdout[:200]}

class OutreachEmailTool(OutreachTool):
    """Tool to generate personalized outreach emails."""
    
    def __init__(self):
        super().__init__(
            'outreach_email',
            'Generate a personalized, professional outreach email for a security assessment'
        )
    
    def execute(self, company_name: str, contact_name: str, contact_title: str, key_findings: List[str], domain: str) -> Dict[str, Any]:
        """Generate an outreach email using Ollama."""
        findings_text = "\n".join([f"- {f}" for f in key_findings[:3]])
        
        prompt = f"""
        Write a professional outreach email for a web application security assessment.
        
        Recipient: {contact_name}, {contact_title} at {company_name}
        Company Domain: {domain}
        Key findings to highlight:
        {findings_text}
        
        Email should:
        1. Be brief (3-4 paragraphs)
        2. Lead with findings relevant to their business
        3. Explain the impact without being alarmist
        4. Propose a simple next step (call, meeting)
        5. Include a brief credentials line
        
        Return ONLY the email body, no other text. No subject line needed.
        """
        
        result = subprocess.run(
            ['ollama', 'run', 'gemma4:latest'],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        email = result.stdout.strip()
        return {'status': 'success', 'email': email}

class ProposalGeneratorTool(OutreachTool):
    """Tool to generate a professional proposal/SOW."""
    
    def __init__(self):
        super().__init__(
            'proposal_generator',
            'Generate a professional proposal or statement of work for a security assessment engagement'
        )
    
    def execute(self, company_name: str, domain: str, vulnerabilities: List[str], estimated_budget: str) -> Dict[str, Any]:
        """Generate a proposal using Ollama."""
        vuln_list = "\n".join([f"- {v}" for v in vulnerabilities[:5]])
        
        prompt = f"""
        Generate a brief professional proposal for a web application security assessment.
        
        Company: {company_name}
        Domain: {domain}
        Key vulnerabilities to address:
        {vuln_list}
        
        Estimated company budget tier: {estimated_budget}
        
        Proposal should include:
        1. Executive Summary
        2. Scope (3-4 deliverables)
        3. Timeline (2-3 weeks)
        4. Pricing (appropriate for their budget tier)
        5. Next Steps
        
        Keep it to 1 page. Format as Markdown.
        Return ONLY the proposal, no other text.
        """
        
        result = subprocess.run(
            ['ollama', 'run', 'gemma4:latest'],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        proposal = result.stdout.strip()
        return {'status': 'success', 'proposal': proposal}

class OutreachAgent:
    """Autonomous agent for managing outreach to a target company."""
    
    def __init__(self, company_name: str, domain: str):
        self.company_name = company_name
        self.domain = domain
        self.tools = {
            'research': CompanyResearchTool(),
            'assessment': VulnerabilityAssessmentTool(),
            'email': OutreachEmailTool(),
            'proposal': ProposalGeneratorTool(),
        }
        self.state = {}
    
    def run(self) -> Dict[str, Any]:
        """Execute the full outreach workflow for this company."""
        print(f"\n{'='*80}")
        print(f"OUTREACH AGENT: {self.company_name}")
        print(f"{'='*80}\n")
        
        # Step 1: Research
        print(f"[1] Researching {self.company_name}...")
        research = self.tools['research'].execute(
            company_name=self.company_name,
            domain=self.domain
        )
        if research['status'] == 'success':
            self.state['research'] = research['data']
            print(f"    ✓ Research complete")
        else:
            print(f"    ✗ Research failed: {research['message']}")
            return {'status': 'failed', 'reason': 'research'}
        
        # Step 2: Vulnerability Assessment
        print(f"[2] Assessing vulnerabilities...")
        tech_stack = self.state['research'].get('tech_stack', 'Unknown')
        security_posture = self.state['research'].get('security_observations', 'Unknown')
        
        assessment = self.tools['assessment'].execute(
            company_name=self.company_name,
            tech_stack=tech_stack,
            security_posture=security_posture
        )
        if assessment['status'] == 'success':
            self.state['vulnerabilities'] = assessment['vulnerabilities']
            print(f"    ✓ Found {len(assessment['vulnerabilities'])} vulnerability classes")
        else:
            print(f"    ✗ Assessment failed: {assessment['message']}")
            return {'status': 'failed', 'reason': 'assessment'}
        
        # Step 3: Generate Email
        print(f"[3] Generating outreach email...")
        contact_titles = self.state['research'].get('contact_titles', ['Security Lead'])
        contact_title = contact_titles[0] if contact_titles else 'Security Team'
        contact_name = f"{contact_title.split()[0]}"  # Use first word as placeholder
        
        key_findings = [v.get('type', 'Security Issue') for v in self.state['vulnerabilities'][:3]]
        
        email_result = self.tools['email'].execute(
            company_name=self.company_name,
            contact_name=contact_name,
            contact_title=contact_title,
            key_findings=key_findings,
            domain=self.domain
        )
        if email_result['status'] == 'success':
            self.state['email'] = email_result['email']
            print(f"    ✓ Email generated ({len(email_result['email'].split())} words)")
        else:
            print(f"    ✗ Email generation failed")
            return {'status': 'failed', 'reason': 'email'}
        
        # Step 4: Generate Proposal
        print(f"[4] Generating proposal...")
        vuln_types = [v.get('type', 'Security Issue') for v in self.state['vulnerabilities']]
        est_budget = self.state['research'].get('estimated_budget', 'mid-market')
        
        proposal_result = self.tools['proposal'].execute(
            company_name=self.company_name,
            domain=self.domain,
            vulnerabilities=vuln_types,
            estimated_budget=est_budget
        )
        if proposal_result['status'] == 'success':
            self.state['proposal'] = proposal_result['proposal']
            print(f"    ✓ Proposal generated")
        else:
            print(f"    ✗ Proposal generation failed")
            return {'status': 'failed', 'reason': 'proposal'}
        
        print(f"\n{'='*80}")
        print(f"OUTREACH PACKAGE COMPLETE FOR {self.company_name}")
        print(f"{'='*80}\n")
        
        return {
            'status': 'success',
            'company': self.company_name,
            'domain': self.domain,
            'state': self.state
        }

def run_outreach_agent_for_company(company_name: str, domain: str) -> Dict[str, Any]:
    """Run a complete outreach workflow for a single company."""
    agent = OutreachAgent(company_name, domain)
    return agent.run()

if __name__ == '__main__':
    # Example usage
    result = run_outreach_agent_for_company('Example Corp', 'example.com')
    print("\nAgent output:")
    print(json.dumps(result, indent=2))
