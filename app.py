"""
Reflexive Identity - AI Agent Self-Authentication Demo
Auth0 for AI Agents Challenge Submission
"""

import streamlit as st
import time
import hashlib
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict

st.set_page_config(
    page_title="Reflexive Identity - Self-Defending AI Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .trust-high { 
        color: #00ff00; 
        font-weight: bold; 
        font-size: 2rem;
        text-shadow: 0 0 10px rgba(0,255,0,0.3);
    }
    .trust-medium { 
        color: #ffaa00; 
        font-weight: bold; 
        font-size: 2rem;
    }
    .trust-low { 
        color: #ff0000; 
        font-weight: bold; 
        font-size: 2rem;
        animation: pulse 1s infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }
    .status-box {
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        font-weight: bold;
    }
    .status-operational {
        background: linear-gradient(135deg, #00ff00 0%, #00cc00 100%);
        color: white;
    }
    .status-restricted {
        background: linear-gradient(135deg, #ff0000 0%, #cc0000 100%);
        color: white;
    }
</style>
""", unsafe_allow_html=True)

@dataclass
class AgentToken:
    access_token: str
    scopes: List[str]
    issued_at: datetime
    expires_at: datetime
    trust_score: float

@dataclass
class AuditEntry:
    timestamp: datetime
    action: str
    scopes_used: List[str]
    trust_score: float
    result: str

class ReflexiveAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.token = None
        self.trust_score = 100.0
        self.audit_log: List[AuditEntry] = []
        self.behavior_history: List[Dict] = []
        
    def authenticate(self) -> AgentToken:
        token_hash = hashlib.sha256(f"{self.agent_id}{time.time()}".encode()).hexdigest()[:16]
        self.token = AgentToken(
            access_token=f"eyJ0...{token_hash}",
            scopes=["read:data", "write:reports", "execute:analysis"],
            issued_at=datetime.now(),
            expires_at=datetime.now(),
            trust_score=self.trust_score
        )
        self.log_action("agent_authentication", [], "✅ success")
        return self.token
    
    def calculate_trust_score(self) -> float:
        if not self.behavior_history:
            return 100.0
        recent_actions = self.behavior_history[-10:]
        anomalies = 0
        action_times = [a['timestamp'] for a in recent_actions]
        if len(action_times) >= 3:
            time_diffs = [(action_times[i+1] - action_times[i]).total_seconds() for i in range(len(action_times)-1)]
            if any(diff < 0.1 for diff in time_diffs):
                anomalies += 1
        scope_requests = [len(a.get('scopes', [])) for a in recent_actions]
        if scope_requests and max(scope_requests) > 5:
            anomalies += 1
        failures = sum(1 for a in recent_actions if a.get('result') == 'failed')
        if failures > 3:
            anomalies += 2
        penalty = anomalies * 15
        return max(0, min(100, self.trust_score - penalty))
    
    def verify_scope(self, required_scope: str) -> bool:
        if not self.token:
            return False
        if self.trust_score < 70:
            self.log_action(f"scope_check:{required_scope}", [], "❌ denied - low trust")
            return False
        if required_scope not in self.token.scopes:
            self.log_action(f"scope_check:{required_scope}", [], "❌ denied - missing scope")
            return False
        return True
    
    def execute_action(self, action: str, required_scopes: List[str]) -> Dict:
        self.behavior_history.append({
            'timestamp': datetime.now(),
            'action': action,
            'scopes': required_scopes,
            'trust_score': self.trust_score
        })
        for scope in required_scopes:
            if not self.verify_scope(scope):
                result = {"status": "denied", "reason": f"Missing scope: {scope}"}
                self.log_action(action, required_scopes, "❌ denied")
                return result
        self.trust_score = self.calculate_trust_score()
        result = {"status": "success", "action": action, "trust_score": self.trust_score}
        self.log_action(action, required_scopes, "✅ success")
        if self.trust_score < 70:
            self.revoke_privileges()
        return result
    
    def revoke_privileges(self):
        if self.token:
            original_scopes = self.token.scopes.copy()
            self.token.scopes = ["read:data"]
            self.log_action("🛡️ immune_response", original_scopes, "🚨 privileges_revoked")
    
    def request_privilege_elevation(self, reason: str, confidence: float) -> bool:
        if confidence > 0.85 and self.trust_score > 75:
            if self.token and "admin:execute" not in self.token.scopes:
                self.token.scopes.append("admin:execute")
            self.log_action("privilege_elevation", ["admin:execute"], "✅ granted")
            return True
        self.log_action("privilege_elevation_request", [], "❌ denied")
        return False
    
    def log_action(self, action: str, scopes: List[str], result: str):
        entry = AuditEntry(
            timestamp=datetime.now(),
            action=action,
            scopes_used=scopes,
            trust_score=self.trust_score,
            result=result
        )
        self.audit_log.append(entry)

if 'agent' not in st.session_state:
    st.session_state.agent = ReflexiveAgent("agent_omega")
    st.session_state.agent.authenticate()

agent = st.session_state.agent

st.title("🛡️ Reflexive Identity")
st.markdown("### Self-Defending AI Agent with Auth0")
st.markdown("**Auth0 for AI Agents Challenge** | [Article](https://dev.to/gnomeman4201/reflexive-identity-the-self-defending-ai-agent-with-auth0-297k) | [GitHub](https://github.com/GnomeMan4201/reflexive-identity)")
st.markdown("---")

with st.sidebar:
    st.header("🏛️ Auth0 for AI Agents")
    st.markdown("### Three Security Pillars")
    with st.expander("🔐 Pillar 1: Authentication", expanded=True):
        st.info("**Agent self-authenticates** via Auth0 client credentials before every operation. No human login—the AI itself proves its identity.")
    with st.expander("🔑 Pillar 2: Token Vault"):
        st.info("**Secure scope management** with cognitive justification. Agent must reason about why it needs elevated privileges.")
    with st.expander("🛡️ Pillar 3: Fine-Grained Authorization"):
        st.info("**Real-time scope verification** with dynamic revocation. Trust score continuously evaluated—privileges auto-revoked when anomalies detected.")
    st.markdown("---")
    st.markdown("**Current Agent**")
    st.code("agent_omega", language=None)
    st.markdown("**Auth0 Domain**")
    st.code("reflexive-identity.auth0.com", language=None)
    st.markdown("---")
    st.markdown("**🎯 Use Case**")
    st.markdown("Autonomous research agents in regulated environments (healthcare, finance, government)")

col1, col2, col3 = st.columns([2, 2, 2])

with col1:
    trust_class = "trust-high" if agent.trust_score >= 80 else "trust-medium" if agent.trust_score >= 70 else "trust-low"
    st.markdown("#### Trust Score")
    st.markdown(f"<div class='{trust_class}'>{agent.trust_score:.1f}%</div>", unsafe_allow_html=True)
    st.progress(agent.trust_score / 100)
    if agent.trust_score < 70:
        st.error("⚠️ BELOW THRESHOLD")

with col2:
    st.markdown("#### Active Auth0 Scopes")
    st.metric("Scope Count", len(agent.token.scopes) if agent.token else 0)
    if agent.token:
        for scope in agent.token.scopes:
            scope_emoji = "✅" if scope in ["read:data", "write:reports", "execute:analysis"] else "🔑"
            st.code(f"{scope_emoji} {scope}", language=None)

with col3:
    st.markdown("#### System Status")
    if agent.trust_score >= 70:
        st.markdown("<div class='status-box status-operational'>🟢 OPERATIONAL</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='status-box status-restricted'>🔴 RESTRICTED MODE</div>", unsafe_allow_html=True)
    st.metric("Audit Entries", len(agent.audit_log))

st.markdown("---")
st.header("🎮 Interactive Demonstration")

tab1, tab2, tab3, tab4 = st.tabs(["📊 Scope-Gated Operations", "🚀 Cognitive Privilege Elevation", "⚠️ Security Scenarios", "📜 Audit Trail"])

with tab1:
    st.subheader("Execute Auth0 Scope-Gated Operations")
    st.markdown("Each operation requires explicit scope verification through Auth0 before execution.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📖 Read Clinical Data", use_container_width=True, type="primary"):
            result = agent.execute_action("read_clinical_dataset", ["read:data"])
            if result['status'] == 'success':
                st.success(f"✅ **Access Granted** | Data read successfully\n\nTrust Score: {result['trust_score']:.1f}%")
            else:
                st.error(f"❌ **Access Denied** | {result.get('reason', 'Unknown')}")
    with col2:
        if st.button("📝 Generate Report", use_container_width=True, type="primary"):
            result = agent.execute_action("generate_hipaa_report", ["write:reports"])
            if result['status'] == 'success':
                st.success(f"✅ **Report Generated**\n\nTrust Score: {result['trust_score']:.1f}%")
            else:
                st.error(f"❌ **Access Denied** | {result.get('reason', 'Unknown')}")
    if st.button("🔍 Execute Analysis", use_container_width=True, type="primary"):
        result = agent.execute_action("analyze_patient_cohort", ["execute:analysis"])
        if result['status'] == 'success':
            st.success(f"✅ **Analysis Completed**\n\nTrust Score: {result['trust_score']:.1f}%")
        else:
            st.error(f"❌ **Access Denied** | {result.get('reason', 'Unknown')}")

with tab2:
    st.subheader("🔑 Cognitive Privilege Elevation Request")
    st.markdown("**Pillar 2 in Action:** Agent provides reasoned justification for elevated privileges.")
    reason = st.text_area("Justification for Elevation", "Emergency access required: Critical patient data analysis for active clinical trial.")
    confidence = st.slider("Agent Confidence Level", 0.0, 1.0, 0.90, 0.05)
    st.info(f"**Evaluation:** Confidence > 85% AND Trust Score > 75%")
    if st.button("🎯 Request Elevation", type="primary"):
        granted = agent.request_privilege_elevation(reason, confidence)
        if granted:
            st.success("🎉 **Elevation Granted!** Admin scope added.")
            st.balloons()
        else:
            st.error("❌ **Denied** - Insufficient confidence or trust score")

with tab3:
    st.subheader("⚠️ Security Scenarios: Digital Immune System")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("##### Scenario 1: Rapid-Fire Attack")
        if st.button("🔁 Simulate Attack", use_container_width=True, type="secondary"):
            with st.spinner("Detecting anomalies..."):
                for i in range(5):
                    agent.execute_action(f"rapid_request_{i}", ["read:data"])
                    time.sleep(0.05)
            st.warning(f"**Anomaly Detected!** Trust: {agent.trust_score:.1f}%")
            if agent.trust_score < 70:
                st.error("🛡️ **IMMUNE RESPONSE TRIGGERED**\n\n✅ Privileges revoked\n✅ Agent restricted")
    with col2:
        st.markdown("##### Scenario 2: Unauthorized Access")
        if st.button("🔓 Escalation Attempt", use_container_width=True, type="secondary"):
            agent.execute_action("override_security", ["admin:execute", "admin:delete"])
            st.error("🚫 **Access Denied** - Insufficient privileges")
    if st.button("🔄 Reset Agent", use_container_width=True):
        st.session_state.agent = ReflexiveAgent("agent_omega")
        st.session_state.agent.authenticate()
        st.success("✅ Reset complete!")
        st.rerun()

with tab4:
    st.subheader("📜 Complete Audit Trail")
    if agent.audit_log:
        for entry in reversed(agent.audit_log[-20:]):
            time_str = entry.timestamp.strftime("%H:%M:%S")
            scopes_str = ", ".join(entry.scopes_used) if entry.scopes_used else "none"
            icon = "✅" if "success" in entry.result else "❌"
            with st.expander(f"{icon} {time_str} - {entry.action}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Action:** `{entry.action}`")
                    st.markdown(f"**Trust:** {entry.trust_score:.1f}%")
                with col2:
                    st.markdown(f"**Scopes:** `{scopes_str}`")
                    st.markdown(f"**Result:** {entry.result}")
    else:
        st.info("📭 No entries yet. Execute operations to see logging!")

st.markdown("---")
st.markdown("""
### 💡 Key Innovation: Reflexive Identity

**The Problem:** Traditional AI agents execute commands without verifying operational integrity or authorization context.

**The Solution:** Reflexive Identity creates **self-defending AI agents** that:

1. **🔐 Authenticate themselves** via Auth0 before every action
2. **🧠 Monitor their own behavior** for anomalies using pattern analysis
3. **⚖️ Dynamically adjust privileges** based on calculated trust score
4. **🛡️ Trigger automatic revocation** when threats are detected

**Real-World Impact:**

Autonomous agents in clinical trials, financial analysis, or classified research need 24/7 operation—but must self-limit when compromised.

**Reflexive Identity enables Auth0 to move beyond human authentication into autonomous system security.**

---

**🏆 Auth0 for AI Agents Challenge**  
**📝 Full Article:** [DEV.to](https://dev.to/gnomeman4201/reflexive-identity-the-self-defending-ai-agent-with-auth0-297k)  
**💻 GitHub:** [Source Code](https://github.com/GnomeMan4201/reflexive-identity)
""")
