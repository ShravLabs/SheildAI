import { useState, useEffect, useRef } from "react";

const API = "http://localhost:8000";

const LABEL_COLORS = {
  clean:      { bg: "#00D68F20", border: "#00D68F", text: "#00D68F" },
  ddos:       { bg: "#E8454520", border: "#E84545", text: "#E84545" },
  sqli:       { bg: "#FF7A2920", border: "#FF7A29", text: "#FF7A29" },
  suspicious: { bg: "#FFD16620", border: "#FFD166", text: "#FFD166" },
};

const LABEL_EMOJI = { clean: "✅", ddos: "🔴", sqli: "🟠", suspicious: "🟡" };

function StatCard({ title, value, sub, color = "#00C9FF" }) {
  return (
    <div style={{
      background: "#0D1540", border: `1px solid ${color}33`,
      borderRadius: 12, padding: "18px 22px", minWidth: 140, flex: 1
    }}>
      <div style={{ color: "#8899BB", fontSize: 12, marginBottom: 6 }}>{title}</div>
      <div style={{ color, fontSize: 28, fontWeight: 700 }}>{value}</div>
      {sub && <div style={{ color: "#8899BB", fontSize: 11, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function ThreatRow({ event }) {
  const c = LABEL_COLORS[event.label] || LABEL_COLORS.clean;
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12,
      padding: "10px 16px", borderBottom: "1px solid #0E1E5C",
      fontSize: 13
    }}>
      <span style={{ color: "#8899BB", width: 75, flexShrink: 0 }}>
        {event.timestamp?.slice(11, 19)}
      </span>
      <span style={{
        background: c.bg, border: `1px solid ${c.border}`,
        color: c.text, borderRadius: 6, padding: "2px 10px",
        fontWeight: 700, width: 90, textAlign: "center", flexShrink: 0
      }}>
        {LABEL_EMOJI[event.label]} {event.label?.toUpperCase()}
      </span>
      <span style={{ color: "#B0C0E0", width: 120, flexShrink: 0 }}>{event.ip}</span>
      <span style={{ color: "#8899BB", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{event.path}</span>
      <span style={{ color: event.threat_score > 0.6 ? "#E84545" : "#00D68F", width: 50, textAlign: "right", flexShrink: 0 }}>
        {(event.threat_score * 100).toFixed(0)}%
      </span>
      <span style={{
        background: event.action === "BLOCKED" ? "#E8454520" : "#00D68F10",
        color: event.action === "BLOCKED" ? "#E84545" : "#00D68F",
        border: `1px solid ${event.action === "BLOCKED" ? "#E84545" : "#00D68F"}`,
        borderRadius: 4, padding: "1px 8px", fontSize: 11, flexShrink: 0
      }}>
        {event.action}
      </span>
    </div>
  );
}

export default function App() {
  const [stats, setStats] = useState(null);
  const [threats, setThreats] = useState([]);
  const [blocked, setBlocked] = useState([]);
  const [tab, setTab] = useState("live");
  const [simulating, setSimulating] = useState(false);
  const simRef = useRef(false);

  const fetchData = async () => {
    try {
      const [s, t, b] = await Promise.all([
        fetch(`${API}/stats`).then(r => r.json()),
        fetch(`${API}/threats?limit=30`).then(r => r.json()),
        fetch(`${API}/blocked-ips`).then(r => r.json()),
      ]);
      setStats(s);
      setThreats(t.events || []);
      setBlocked(b.ips || []);
    } catch {
      // backend not running — use demo data
      setStats({ total_requests: 1240, blocked_ips: 7, threat_rate: 0.28, label_distribution: { clean: 893, ddos: 187, sqli: 98, suspicious: 62 } });
    }
  };

  useEffect(() => { fetchData(); const id = setInterval(fetchData, 3000); return () => clearInterval(id); }, []);

  // Traffic simulator
  const simulate = async () => {
    if (simulating) { simRef.current = false; setSimulating(false); return; }
    simRef.current = true;
    setSimulating(true);
    const ips = ["45.33.32.156", "192.168.1.101", "103.22.44.99", "81.200.12.44", "172.16.0.5"];
    const paths = ["/api/users", "/login", "/search?q=test", "/admin", "/api/data"];
    const scenarios = [
      { request_rate: 5, payload_size: 400, unique_endpoints: 2, error_rate: 0.01, has_sql_keywords: 0, header_anomaly: 0, geo_risk_score: 0.1, repeated_ip: 0 },
      { request_rate: 950, payload_size: 90, unique_endpoints: 1, error_rate: 0.8, has_sql_keywords: 0, header_anomaly: 1, geo_risk_score: 0.9, repeated_ip: 1 },
      { request_rate: 6, payload_size: 2400, unique_endpoints: 8, error_rate: 0.35, has_sql_keywords: 1, header_anomaly: 0, geo_risk_score: 0.5, repeated_ip: 0 },
      { request_rate: 55, payload_size: 700, unique_endpoints: 12, error_rate: 0.15, has_sql_keywords: 0, header_anomaly: 1, geo_risk_score: 0.4, repeated_ip: 1 },
    ];
    while (simRef.current) {
      const ip = ips[Math.floor(Math.random() * ips.length)];
      const path = paths[Math.floor(Math.random() * paths.length)];
      const sc = scenarios[Math.floor(Math.random() * scenarios.length)];
      try {
        await fetch(`${API}/classify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip, path, method: "POST", ...sc })
        });
        await fetchData();
      } catch { break; }
      await new Promise(r => setTimeout(r, 800));
    }
    setSimulating(false);
  };

  const unblockIp = async (ip) => {
    try {
      await fetch(`${API}/block/${ip}`, { method: "DELETE" });
      await fetchData();
    } catch {}
  };

  const dist = stats?.label_distribution || {};
  const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;

  return (
    <div style={{ background: "#0A0F2C", minHeight: "100vh", color: "#E8EEF7", fontFamily: "Trebuchet MS, sans-serif" }}>
      {/* Header */}
      <div style={{ background: "#0D1540", borderBottom: "1px solid #1A3A8F", padding: "14px 28px", display: "flex", alignItems: "center", gap: 16 }}>
        <span style={{ fontSize: 24 }}>🛡️</span>
        <span style={{ fontSize: 22, fontWeight: 700, color: "#00C9FF" }}>ShieldAI</span>
        <span style={{ color: "#8899BB", fontSize: 13 }}>Cloud Security Intelligence Platform</span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 10, alignItems: "center" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: simulating ? "#00D68F" : "#8899BB", display: "inline-block", animation: simulating ? "pulse 1s infinite" : "none" }} />
          <span style={{ fontSize: 12, color: simulating ? "#00D68F" : "#8899BB" }}>{simulating ? "LIVE" : "IDLE"}</span>
          <button onClick={simulate} style={{
            background: simulating ? "#E8454520" : "#00C9FF20",
            color: simulating ? "#E84545" : "#00C9FF",
            border: `1px solid ${simulating ? "#E84545" : "#00C9FF"}`,
            borderRadius: 8, padding: "6px 16px", cursor: "pointer", fontWeight: 700, fontSize: 13
          }}>
            {simulating ? "⏹ Stop" : "▶ Simulate Traffic"}
          </button>
        </div>
      </div>

      <div style={{ padding: "24px 28px" }}>
        {/* Stats Row */}
        <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
          <StatCard title="Total Requests" value={stats?.total_requests ?? "–"} sub="since startup" color="#00C9FF" />
          <StatCard title="Blocked IPs" value={stats?.blocked_ips ?? "–"} sub="auto-blocked" color="#E84545" />
          <StatCard title="Threat Rate" value={stats ? `${(stats.threat_rate * 100).toFixed(1)}%` : "–"} sub="of all traffic" color="#FFD166" />
          <StatCard title="Clean Traffic" value={dist.clean ?? "–"} sub="requests allowed" color="#00D68F" />
          <StatCard title="DDoS Detected" value={dist.ddos ?? "–"} sub="flood attempts" color="#E84545" />
          <StatCard title="SQL Injection" value={dist.sqli ?? "–"} sub="injection attempts" color="#FF7A29" />
        </div>

        {/* Distribution Bar */}
        {total > 1 && (
          <div style={{ marginBottom: 24 }}>
            <div style={{ color: "#8899BB", fontSize: 12, marginBottom: 8 }}>TRAFFIC DISTRIBUTION</div>
            <div style={{ display: "flex", height: 10, borderRadius: 6, overflow: "hidden", gap: 2 }}>
              {Object.entries(dist).map(([label, count]) => (
                <div key={label} style={{
                  width: `${(count / total) * 100}%`,
                  background: LABEL_COLORS[label]?.border || "#8899BB",
                  transition: "width 0.5s"
                }} title={`${label}: ${count}`} />
              ))}
            </div>
            <div style={{ display: "flex", gap: 16, marginTop: 8 }}>
              {Object.entries(dist).map(([label, count]) => (
                <span key={label} style={{ fontSize: 11, color: LABEL_COLORS[label]?.text || "#8899BB" }}>
                  {LABEL_EMOJI[label]} {label} ({((count / total) * 100).toFixed(1)}%)
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Tabs */}
        <div style={{ display: "flex", gap: 4, marginBottom: 16 }}>
          {["live", "blocked"].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: tab === t ? "#1A3A8F" : "transparent",
              color: tab === t ? "#00C9FF" : "#8899BB",
              border: `1px solid ${tab === t ? "#1A3A8F" : "#1A3A8F44"}`,
              borderRadius: 8, padding: "6px 18px", cursor: "pointer", fontWeight: 600, fontSize: 13
            }}>
              {t === "live" ? `📡 Live Feed (${threats.length})` : `🚫 Blocked IPs (${blocked.length})`}
            </button>
          ))}
        </div>

        {/* Content */}
        <div style={{ background: "#0D1540", borderRadius: 12, border: "1px solid #1A3A8F", overflow: "hidden" }}>
          {tab === "live" ? (
            <>
              <div style={{ display: "flex", padding: "8px 16px", borderBottom: "1px solid #0E1E5C", fontSize: 11, color: "#8899BB", gap: 12 }}>
                <span style={{ width: 75 }}>TIME</span>
                <span style={{ width: 90 }}>LABEL</span>
                <span style={{ width: 120 }}>IP</span>
                <span style={{ flex: 1 }}>PATH</span>
                <span style={{ width: 50, textAlign: "right" }}>THREAT</span>
                <span style={{ width: 60 }}>ACTION</span>
              </div>
              {threats.length === 0 ? (
                <div style={{ padding: 40, textAlign: "center", color: "#8899BB" }}>
                  No traffic yet. Click <strong style={{ color: "#00C9FF" }}>▶ Simulate Traffic</strong> to start.
                </div>
              ) : (
                threats.map(e => <ThreatRow key={e.id} event={e} />)
              )}
            </>
          ) : (
            <div>
              {blocked.length === 0 ? (
                <div style={{ padding: 40, textAlign: "center", color: "#8899BB" }}>
                  No IPs blocked yet. Run simulation to trigger auto-block.
                </div>
              ) : blocked.map(b => (
                <div key={b.ip} style={{ display: "flex", alignItems: "center", gap: 16, padding: "12px 16px", borderBottom: "1px solid #0E1E5C" }}>
                  <span style={{ color: "#E84545", fontWeight: 700 }}>🚫 {b.ip}</span>
                  <span style={{ color: "#8899BB", flex: 1, fontSize: 13 }}>{b.reason}</span>
                  <span style={{ color: "#8899BB", fontSize: 12 }}>{b.blocked_at?.slice(0, 19)}</span>
                  <button onClick={() => unblockIp(b.ip)} style={{
                    background: "#00D68F10", color: "#00D68F", border: "1px solid #00D68F",
                    borderRadius: 6, padding: "4px 12px", cursor: "pointer", fontSize: 12
                  }}>Unblock</button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #0A0F2C; } ::-webkit-scrollbar-thumb { background: #1A3A8F; border-radius: 3px; }
      `}</style>
    </div>
  );
}
