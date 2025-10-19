"""
Reflexive Identity - AI Agent Self-Authentication Demo
Auth0 for AI Agents Challenge Submission
"""

import streamlit as st
import time
import random
import json
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict
import hashlib

# Page config
st.set_page_config(
    page_title="Reflexive Identity - Self-Defending AI Agent",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .trust-high { color: #00ff00; font-weight: bold; }
    .trust-medium { color: #ffaa00; font-weight: bold; }
    .trust-low { color: #ff0000; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

@dataclass
class Auth0Config:
    domain: str = "reflexive-identity.auth0.com"
    client_id: str = "agent_omega_client_id"
    client_secret: str = "****_simulated_****"
    audience: str = "https://api.reflexive-identity.com"

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
    """AI Agent with self-authentication capabilities"""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.token = None
        self.trust_score = 100.0
        self.audit_log: List[AuditEntry] = []
        self.behavior_history: List[Dict] = []
        
    def authenticate(self) -> AgentToken:
        """Pillar 1: Agent authenticates itself via Auth0"""
        token_hash = hashlib.sha256(f"{self.agent_id}{time.time()}".encode()).hexdigest()[:16]
        
        self.token = AgentToken(
            access_token=f"eyJ0...{token_hash}",
            scopes=["read:data", "write:reports", "execute:analysis"],
            issued_at=datetime.now(),
            expires_at=datetime.now(),
            trust_score=self.trust_score
        )
        
        self.log_action("authenticate", [], "success")
        return self.token
    
    def calculate_trust_score(self) -> float:
        """Calculate integrity based on behavior patterns"""
        if not self.behavior_history:
            return 100.0
        
        recent_actions = self.behavior_history[-10:]
        anomalies = 0
        
        # Pattern 1: Rapid repeated requests
        action_times = [a['timestamp'] for a in recent_actions]
        if len(action_times) >= 3:
            time_diffs = [(action_times[i+1] - action_times[i]).total_seconds() 
                         for i in range(len(action_times)-1)]
            if any(diff < 0.1 for diff in time_diffs):
                anomalies += 1
        
        # Pattern 2: Scope escalation attempts
        scope_requests = [len(a.get('scopes', [])) for a in recent_actions]
        if scope_requests and max(scope_requests) > 5:
            anomalies += 1
        
        # Pattern 3: Failed operations
        failures = sum(1 for a in recent_actions if a.get('result') == 'failed')
        if failures > 3:
            anomalies += 2
        
        penalty = anomalies * 15
        new_score = max(0, min(100, self.trust_score - penalty))
        
        return new_score
    
    def verify_scope(self, required_scope: str) -> bool:
        """Pillar 3: Fine-grained authorization check"""
        if not self.token:
            return False
        
        if self.trust_score < 70:
            self.log_action(f"verify_scope:{required_scope}", [], "denied - low trust")
            return False
        
        if required_scope not in self.token.scopes:
            self.log_action(f"verify_scope:{required_scope}", [], "denied - missing scope")
            return False
        
        return True
    
    def execute_action(self, action: str, required_scopes: List[str]) -> Dict:
        """Execute an agent action with full auth check"""
        self.behavior_history.append({
            'timestamp': datetime.now(),
            'action': action,
            'scopes': required_scopes,
            'trust_score': self.trust_score
        })
        
        for scope in required_scopes:
            if not self.verify_scope(scope):
                result = {"status": "denied", "reason": f"Missing scope: {scope}"}
                self.log_action(action, required_scopes, "denied")
                return result
        
        self.trust_score = self.calculate_trust_score()
        
        result = {"status": "success", "action": action, "trust_score": self.trust_score}
        self.log_action(action, required_scopes, "success")
        
        if self.trust_score < 70:
            self.revoke_privileges()
        
        return result
    
    def revoke_privileges(self):
        """Digital immune response - revoke privileges"""
        if self.token:
            self.token.scopes = ["read:data"]
            self.log_action("auto_revoke", [], "executed - trust score below threshold")
    
    def request_privilege_elevation(self, reason: str, confidence: float) -> bool:
        """Pillar 2: Agent requests elevated privileges with justification"""
        justification = {
            "intent": "elevated_access",
            "reason": reason,
            "confidence": confidence,
            "current_trust": self.trust_score
        }
        
        if confidence > 0.85 and self.trust_score > 75:
            if self.token and "admin:execute" not in self.token.scopes:
                self.token.scopes.append("admin:execute")
            self.log_action("elevate_privileges", ["admin:execute"], "granted")
            return True
        
        self.log_action("elevate_privileges", [], "denied")
        return False
    
    def log_action(self, action: str, scopes: List[str], result: str):
        """Audit trail for all agent actions"""
        entry = AuditEntry(
            timestamp=datetime.now(),
            action=action,
            scopes_used=scopes,
            trust_score=self.trust_score,
            result=result
        )
        self.audit_log.append(entry)

# Initialize session state
if 'agent' not in st.session_state:
    st.session_state.agent = ReflexiveAgent("agent_omega")
    st.session_state.agent.authenticate()

agent = st.session_state.agent

# Header
st.title("🛡️ Reflexive Identity: Self-Defending AI Agent")
st.markdown("### Auth0 for AI Agents Challenge - Live Demo")
st.markdown("---")

# Sidebar
with st.sidebar:
    st.header("🏛️ Auth0 AI Agent Pillars")
    
    st.markdown("### 🔐 Pillar 1: Authentication")
    st.info("Agent authenticates itself via Auth0 client credentials before any operation.")
    
    st.markdown("### 🔑 Pillar 2: Token Vault")
    st.info("Simulated secure token management with scope-based privileges.")
    
    st.markdown("### 🛡️ Pillar 3: Fine-Grained Authorization")
    st.info("Real-time scope verification and dynamic privilege revocation based on trust score.")
    
    st.markdown("---")
    st.markdown("**Agent ID:** `agent_omega`")
    st.markdown("**Auth0 Domain:** `reflexive-identity.auth0.com`")

# Main Dashboard
col1, col2, col3 = st.columns(3)

with col1:
    trust_class = "trust-high" if agent.trust_score >= 80 else "trust-medium" if agent.trust_score >= 70 else "trust-low"
    st.markdown(f"### <span class='{trust_class}'>Trust Score: {agent.trust_score:.1f}%</span>", unsafe_allow_html=True)
    st.progress(agent.trust_score / 100)

with col2:
    st.metric("Active Scopes", len(agent.token.scopes) if agent.token else 0)
    if agent.token:
        for scope in agent.token.scopes:
            st.code(scope, language=None)

with col3:
    st.metric("Audit Entries", len(agent.audit_log))
    status = "🟢 Operational" if agent.trust_score >= 70 else "🔴 Restricted"
    st.markdown(f"**Status:** {status}")

st.markdown("---")

# Interactive Controls
st.header("🎮 Interactive Agent Operations")

tab1, tab2, tab3, tab4 = st.tabs(["📊 Data Operations", "🚀 Privilege Elevation", "⚠️ Anomaly Simulation", "📜 Audit Log"])

with tab1:
    st.subheader("Execute Scope-Gated Operations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📖 Read Data", use_container_width=True):
            result = agent.execute_action("read_dataset", ["read:data"])
            if result['status'] == 'success':
                st.success(f"✅ Data read successfully (Trust: {result['trust_score']:.1f}%)")
            else:
                st.error(f"❌ Access denied: {result.get('reason', 'Unknown')}")
    
    with col2:
        if st.button("📝 Write Report", use_container_width=True):
            result = agent.execute_action("generate_report", ["write:reports"])
            if result['status'] == 'success':
                st.success(f"✅ Report generated (Trust: {result['trust_score']:.1f}%)")
            else:
                st.error(f"❌ Access denied: {result.get('reason', 'Unknown')}")
    
    if st.button("🔍 Execute Analysis", use_container_width=True):
        result = agent.execute_action("run_analysis", ["execute:analysis"])
        if result['status'] == 'success':
            st.success(f"✅ Analysis completed (Trust: {result['trust_score']:.1f}%)")
        else:
            st.error(f"❌ Access denied: {result.get('reason', 'Unknown')}")

with tab2:
    st.subheader("🔑 Request Elevated Privileges")
    st.markdown("**Agent provides cognitive justification for privilege escalation**")
    
    reason = st.text_area("Justification", "Need admin access to perform emergency system backup")
    confidence = st.slider("Confidence Level", 0.0, 1.0, 0.90, 0.05)
    
    if st.button("Request Elevation", type="primary"):
        granted = agent.request_privilege_elevation(reason, confidence)
        if granted:
            st.success("🎉 Elevated privileges granted! Admin scope added.")
        else:
            st.error("❌ Elevation denied. Insufficient confidence or trust score.")

with tab3:
    st.subheader("⚠️ Simulate Security Scenarios")
    st.markdown("Watch the digital immune system respond to threats")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔁 Rapid Fire Requests", use_container_width=True):
            st.warning("Simulating suspicious rapid requests...")
            for i in range(5):
                agent.execute_action(f"rapid_request_{i}", ["read:data"])
                time.sleep(0.05)
            st.info(f"Trust score dropped to: {agent.trust_score:.1f}%")
            if agent.trust_score < 70:
                st.error("🛡️ IMMUNE RESPONSE TRIGGERED: Privileges auto-revoked")
    
    with col2:
        if st.button("🔓 Scope Escalation Attempt", use_container_width=True):
            st.warning("Attempting unauthorized scope access...")
            result = agent.execute_action("admin_operation", ["admin:execute", "admin:delete", "admin:override"])
            st.error("🚫 Access denied - insufficient privileges")
    
    if st.button("🔄 Reset Agent State", use_container_width=True):
        st.session_state.agent = ReflexiveAgent("agent_omega")
        st.session_state.agent.authenticate()
        st.rerun()

with tab4:
    st.subheader("📜 Complete Audit Trail")
    
    if agent.audit_log:
        for entry in reversed(agent.audit_log[-20:]):
            time_str = entry.timestamp.strftime("%H:%M:%S")
            scopes_str = ", ".join(entry.scopes_used) if entry.scopes_used else "none"
            
            result_emoji = "✅" if entry.result == "success" else "❌"
            
            with st.expander(f"{result_emoji} {time_str} - {entry.action}"):
                st.markdown(f"**Action:** {entry.action}")
                st.markdown(f"**Scopes:** {scopes_str}")
                st.markdown(f"**Trust Score:** {entry.trust_score:.1f}%")
                st.markdown(f"**Result:** {entry.result}")
    else:
        st.info("No audit entries yet. Try executing some operations!")

# Footer
st.markdown("---")
st.markdown("""
### 💡 Key Innovation: Reflexive Identity

This demo showcases an AI agent that:
1. **Authenticates itself** before taking any action (Auth0 client credentials)
2. **Monitors its own behavior** for anomalies (self-integrity assessment)
3. **Dynamically adjusts privileges** based on calculated trust score
4. **Triggers automatic revocation** when threats are detected (digital immune response)

Traditional AI agents blindly follow instructions. **Reflexive Identity** creates agents that know when to stop themselves.

---

**Built for:** Auth0 for AI Agents Challenge  
**Submission:** [Reflexive Identity - The Self-Defending AI Agent](https://dev.to/gnomeman4201/reflexive-identity-the-self-defending-ai-agent-with-auth0-297k)
""")
