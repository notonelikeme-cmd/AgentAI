# Autonomous Outreach Engine - Execution Plan

## Phase 1: Launch & Validation (Week 1)

### Day 1: Test the System
- [ ] Run company discovery: `python3 outreach_engine.py`
- [ ] Review generated scores in `targets/scored_companies_*.csv`
- [ ] Review outreach packages in `targets/outreach_packages_*.json`
- [ ] Verify that high-score companies (70+) match your target profile
- [ ] Check generated emails and proposals for quality

**Success Criteria:**
- At least 3 companies scoring 75+
- Emails are professional and compelling
- Proposals include realistic pricing for company size

### Day 2-3: Customize & Validate
- [ ] Adjust search terms in `outreach_engine.py` to match your target industries
  - Example: Change "SaaS, fintech, e-commerce" to "FinTech, DeFi, Web3" if focusing on crypto
- [ ] Re-run discovery with adjusted terms
- [ ] Review results and validate that scoring matches your assessment
- [ ] Spot-check 3-5 companies to ensure scoring accuracy
- [ ] Create a "target profile" document (size, budget, security gaps you focus on)

**Success Criteria:**
- Discovery results match your target profile
- You can manually validate scoring is accurate
- You have a clear target profile defined

### Day 4-5: Manual Outreach Test
- [ ] Select 1 company you already know is good candidate
- [ ] Run agent on that company: `python3 outreach_agent.py "Company Name" "domain.com"`
- [ ] Review generated email and proposal
- [ ] Customize email (add your name, contact info, any specific details)
- [ ] Send manually as a test
- [ ] Track response

**Success Criteria:**
- You can manually customize and send outreach
- You've done at least one test outreach
- You understand the workflow end-to-end

### Day 6-7: Document & Refine
- [ ] Document what worked and what didn't
- [ ] Refine prompts in `outreach_agent.py` based on email/proposal quality
- [ ] Create a standard "customization checklist" for emails
- [ ] Update your target list with initial outreach results

**Success Criteria:**
- You have a documented workflow
- You know how to customize generated materials
- You have feedback on email/proposal quality

---

## Phase 2: Scale to 10 Companies (Week 2)

### Step 1: Batch Scoring (Day 1)
- [ ] Run full discovery: `python3 outreach_engine.py`
- [ ] Extract top 10 companies from scoring results
- [ ] Filter manually if needed (remove any bad fits)
- [ ] Export target list to [target_list_template.csv](memory/target_list_template.csv)

**Columns to fill:**
- Company Name
- Domain
- Industry
- Size
- Security Posture (1-10)
- Business Impact (1-10)
- Budget (1-10)
- Visibility (1-10)
- Bug Bounty Status
- Overall Score
- Contact Email (research manually or from LinkedIn)
- Status (pending, contacted, engaged, etc.)

**Success Criteria:**
- 10 good target companies identified
- Contact email found for at least 8/10
- Scoring validated by you

### Step 2: Batch Agent Generation (Day 2-3)
- [ ] For each of top 5 companies, run: `python3 outreach_agent.py "Company" "domain.com"`
- [ ] Save generated emails and proposals to local files
- [ ] Review and customize each email (add your specific details)
- [ ] Rate quality on 1-10 scale
- [ ] Note what worked and what didn't

**Customization Checklist for Each Email:**
- [ ] Add your actual name and title
- [ ] Add contact info (email, phone, LinkedIn)
- [ ] Add 1-2 company-specific details from research
- [ ] Verify tone matches their industry (formal for enterprise, casual for startup)
- [ ] Check for typos and formatting
- [ ] Verify proposal pricing is appropriate

**Success Criteria:**
- 5 customized emails ready to send
- 5 proposals customized with pricing
- Each customized email takes <10 minutes

### Step 3: Outreach Blitz (Day 4-5)
- [ ] Send 5 customized emails to top companies
- [ ] Log send date, recipient name, company in [target_list_template.csv](memory/target_list_template.csv)
- [ ] Set follow-up reminders for 7 days later
- [ ] Begin generation for companies 6-10 while waiting for responses

**Tracking Template:**
```
Company | Domain | Email | Status | Sent Date | Follow-up Date | Response | Notes
--------|--------|-------|--------|-----------|----------------|----------|-------
```

**Success Criteria:**
- 5 emails sent
- Tracked in your target list
- Follow-ups scheduled

### Step 4: Monitor & Iterate (Day 6-7)
- [ ] Check for responses to first 5 emails
- [ ] Generate outreach for companies 6-10
- [ ] Review feedback if any
- [ ] Adjust email template if needed

**Success Criteria:**
- At least 1 positive response from 5 emails (20% response rate is good)
- 5 more companies ready for outreach
- Documented learnings for next batch

---

## Phase 3: Full Scale (Week 3-4)

### Step 1: Production Pipeline (Day 1-2)
- [ ] Automate discovery runs (e.g., weekly)
- [ ] Maintain running list of top 50 companies scored 70+
- [ ] Organize outreach by priority: score, industry, budget
- [ ] Set up email tracking (if using Gmail, Outlook, or HubSpot)

**Target List Structure:**
```
Tier 1: Score 85+  → Reach out within 24 hours of discovery
Tier 2: Score 75-84 → Reach out within 3 days
Tier 3: Score 70-74 → Reach out within 1 week
Tier 4: Score <70   → Archive but keep for future reference
```

### Step 2: Outreach Cadence (Week 3)
- [ ] Target: 5 new outreach emails per day (35/week)
- [ ] Customize and send in batches of 5
- [ ] Follow up with non-responders after 7 days
- [ ] Second follow-up after 14 days
- [ ] Archive after 3 touches

**Daily Outreach Workflow:**
1. Generate with agent (5 companies)
2. Customize emails (5 × 10 min = 50 min)
3. Send emails
4. Log in tracking spreadsheet
5. Follow up on previous batch if needed

### Step 3: Response Tracking (Week 4)
- [ ] Track responses in target list
- [ ] Categorize: Interested, Not Interested, Need More Info, Schedule Call
- [ ] For "Interested" — follow up with proposal details, call scheduling
- [ ] For "Not Interested" — ask for referral, archive
- [ ] For "Need More Info" — provide specific details requested
- [ ] For "Schedule Call" — set up paid assessment engagement call

### Step 4: Conversion (Week 4)
- [ ] For each engaged company, schedule 30-min call
- [ ] On call: explain scope, pricing, timeline
- [ ] Send formal SOW/proposal
- [ ] Aim for conversion to paid engagement

**Target Metrics:**
- Outreach sent: 35+
- Response rate: 10-20%
- Engaged (calls scheduled): 3-5
- Conversion (paid engagements): 1-2

---

## Phase 4: Money-Making Model (Ongoing)

### Pricing Strategy

**By Company Size & Budget:**

| Size | Annual Revenue | Budget Tier | Assessment Cost | Timeline |
|------|---|---|---|---|
| Startup | <$5M | $2K-5K | $2,500 | 1 week |
| Small | $5M-50M | $5K-10K | $7,500 | 2 weeks |
| Mid-market | $50M-500M | $10K-25K | $15,000 | 2-3 weeks |
| Enterprise | $500M+ | $25K-50K+ | $25,000+ | 3-4 weeks |

**Proposal Structure:**
1. Assessment & Report: [X hours] = $[X]
2. Post-Engagement Support: 30 days = included
3. Optional: Remediation Consulting = $[X]/hour

### Revenue Model

**Conservative Estimate (Month 1):**
- 35 outreach emails
- 15% response = 5 engaged
- 40% conversion = 2 paid assessments
- Average price: $7,500
- **Revenue: $15,000**

**Optimized Estimate (Month 1):**
- 70 outreach emails (2x output)
- 20% response = 14 engaged
- 50% conversion = 7 paid assessments
- Average price: $10,000
- **Revenue: $70,000**

**Scaling (Month 2-3):**
- 100+ outreach emails/month
- Pipeline of 20-30 engaged companies
- 5-10 simultaneous assessments
- **Monthly recurring: $30K-50K+**

### Execution Tactics

**To Hit Revenue Target:**

1. **Improve Response Rate (10% → 15-20%)**
   - Personalize emails more (add company-specific findings)
   - Test different subject lines
   - Test different outreach timing (Tue-Thu, 9-10am)
   - Test different angles (CEO, CTO, Security Lead)

2. **Improve Conversion (40% → 50-60%)**
   - Better proposal customization
   - Competitive pricing vs. bug bounty platforms
   - Emphasize private, paid model advantages
   - Offer free 30-min security consultation call

3. **Increase Outreach Volume**
   - Use agent to generate 10/day instead of 5/day
   - Automate outreach tool integration (optional)
   - Use multiple discovery sources (industry databases, LinkedIn)

4. **Reduce Sales Cycle**
   - Fast turnaround on proposals (same day)
   - Flexible engagement start dates
   - Clear pricing (no negotiation needed for Tier 1-2)
   - Offer starter packages ($2.5K for quick scan)

---

## Success Metrics & KPIs

### Track Weekly

| Metric | Target | Current |
|--------|--------|---------|
| Outreach emails sent | 35 | _ |
| Email open rate | 20%+ | _ |
| Response rate | 15%+ | _ |
| Calls scheduled | 3-5 | _ |
| Proposals sent | 2-3 | _ |
| Paid engagements signed | 1-2 | _ |
| Monthly revenue | $15K+ | _ |

### Track Monthly

- Total outreach sent
- Total responses
- Pipeline value (engaged × avg price)
- Conversion rate
- Average deal size
- Revenue (closed + in-progress)
- Cost per acquisition

---

## Day-by-Day Checklist (Week 1 Startup)

### **Day 1 (Monday)**
- [ ] Run `python3 outreach_engine.py`
- [ ] Review scored companies
- [ ] Create target profile document
- [ ] Spot-check 5 companies manually

### **Day 2 (Tuesday)**
- [ ] Adjust search terms in outreach_engine.py
- [ ] Re-run discovery with new terms
- [ ] Validate results against target profile

### **Day 3 (Wednesday)**
- [ ] Pick 1 test company
- [ ] Run `python3 outreach_agent.py "Company" "domain.com"`
- [ ] Review email and proposal
- [ ] Customize email with your details

### **Day 4 (Thursday)**
- [ ] Send test email to 1 company
- [ ] Research contact for 2nd company
- [ ] Generate outreach for 2nd company

### **Day 5 (Friday)**
- [ ] Customize and send 2nd email
- [ ] Research contacts for companies 3-5
- [ ] Generate outreach for companies 3-5

### **Day 6 (Saturday)**
- [ ] Customize and send 3 more emails (now at 5 total)
- [ ] Compile results document
- [ ] Document what worked, what didn't

### **Day 7 (Sunday)**
- [ ] Plan Week 2 strategy
- [ ] Set up target tracking spreadsheet
- [ ] Prepare for 10-company scale

---

## Tools & Setup

### Required
- Local Ollama with 3 models installed
- Terminal access (you have this)
- Outreach engine scripts (deployed)

### Nice to Have (Optional)
- Email client with tracking (Gmail, Outlook)
- Spreadsheet for target tracking (Google Sheets, Excel)
- LinkedIn for finding contacts
- HubSpot (free tier) for pipeline tracking

### Optional Automation (Future)
- Automated daily discovery runs
- Email delivery tool integration
- Response tracking webhook
- Calendar integration for follow-ups

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Low response rate | Personalize emails, test timing/angles, improve subject lines |
| Low conversion | Better proposal customization, reduce pricing friction, faster turnaround |
| Low outreach volume | Increase discovery searches, batch generate more daily |
| Email marked as spam | Authenticate domain, warm up sender reputation, avoid spam words |
| Companies not interested | Offer free consultation call first, emphasize paid model advantage |
| Takes too long to customize | Refine agent prompts to reduce manual work, create template standardization |

---

## Quick Reference Commands

```bash
# Discover and score companies
python3 /Users/nova/AgentAI/outreach_engine.py

# Generate outreach for a specific company
python3 /Users/nova/AgentAI/outreach_agent.py "Company Name" "domain.com"

# CLI interface
python3 /Users/nova/AgentAI/outreach_cli.py discover
python3 /Users/nova/AgentAI/outreach_cli.py outreach "Company Name" "domain.com"

# Shell wrapper
/Users/nova/AgentAI/outreach_runner.sh discover
/Users/nova/AgentAI/outreach_runner.sh outreach "Company Name" "domain.com"

# View results
open /Users/nova/AgentAI/targets/  # View latest scored companies and outreach packages
```

---

## Success Milestones

- **Week 1:** Validate system, send 5 test emails, understand workflow
- **Week 2:** Send 35 emails, get 5-7 responses, schedule 2-3 calls
- **Week 3:** 70+ emails sent, 10-15 engaged, 3-5 paid engagements in progress
- **Month 1:** 140+ emails, 20-30 engaged, 5-10 paid assessments, $15K-70K revenue
- **Month 2:** Refine based on data, increase to 100+ emails/week, $30K-100K revenue
- **Month 3+:** Scale to $30K-50K+ monthly recurring revenue

---

## Next Action

**START HERE:**
1. Run: `python3 /Users/nova/AgentAI/outreach_engine.py`
2. Review results in: `/Users/nova/AgentAI/targets/`
3. Pick top 5 companies (score 75+)
4. For each, run: `python3 /Users/nova/AgentAI/outreach_agent.py "Company" "domain.com"`
5. Customize and send emails

**Then:**
- Track responses in spreadsheet
- Follow up after 7 days
- Schedule calls with interested companies
- Send proposals and close deals

**Then:**
- Scale volume (more outreach per day)
- Optimize (improve response and conversion rates)
- Automate (reduce manual customization time)
- Grow revenue (from $15K/month to $50K+/month)

That's it. Execute the plan, track metrics, iterate. You should have first paid engagement within 2 weeks.
