import { useState, useEffect, useRef, useCallback } from "react";

const FONTS = `@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');`;

// ── embed the raw log XML inline so the artifact is self-contained ──
// In a real deployment you'd load the file; here we parse a compact version
// and the user can paste/import their own XML via the UI.

const SEVERITY = {
  // Sysmon
  "1":  { label:"Process Create",    color:"#f59e0b", cat:"process" },
  "3":  { label:"Network Connect",   color:"#3b82f6", cat:"network" },
  "10": { label:"Process Access",    color:"#ef4444", cat:"process" },
  "11": { label:"File Created",      color:"#8b5cf6", cat:"file"    },
  "22": { label:"DNS Query",         color:"#06b6d4", cat:"network" },
  // Windows Security
  "4624":{ label:"Logon Success",    color:"#10b981", cat:"auth"    },
  "4648":{ label:"Explicit Logon",   color:"#f97316", cat:"auth"    },
  "4688":{ label:"Process Create(W)",color:"#eab308", cat:"process" },
  // System
  "7045":{ label:"Service Install",  color:"#ec4899", cat:"system"  },
};

const CAT_COLORS = { process:"#f59e0b", network:"#3b82f6", file:"#8b5cf6", auth:"#10b981", system:"#ec4899" };

const FLAGS = [
  { id:"FLAG1", pattern:/CTF\{m4cr0_3x3cut10n_d3t3ct3d\}/, hint:"Look at Sysmon EID 1 — what spawned cmd.exe?", act:1 },
  { id:"FLAG2", pattern:/CTF\{d0m41n_3num3r4t10n_succ3ss\}/, hint:"EID 11 — check filenames in AppData\\Temp", act:2 },
  { id:"FLAG3", pattern:/CTF\{p53x3c_l4t3r4l_m0v3m3nt\}/, hint:"EID 1 — search for psexec in CommandLine", act:3 },
  { id:"FLAG4", pattern:/CTF\{cr3d3nt14l_dump_0x1FFFFF\}/, hint:"EID 11 — svchost32.exe dropped a file", act:4 },
  { id:"FLAG5", pattern:/CTF\{d4t4_3xf1ltr4t3d_185_220\}/, hint:"EID 1 — Invoke-WebRequest with POST", act:5 },
];

// ── XML parser ──
function parseEvents(xmlStr) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlStr, "application/xml");
  if (doc.querySelector("parsererror")) return { error: "XML parse error — check file format." };
  const nodes = doc.querySelectorAll("Event");
  const evts = [];
  nodes.forEach((node, idx) => {
    const get = (name) => {
      const el = node.querySelector(`Data[Name="${name}"]`);
      return el ? el.textContent.trim() : "";
    };
    const eid = node.querySelector("EventID")?.textContent?.trim() || "?";
    const timeRaw = node.querySelector("TimeCreated")?.getAttribute("SystemTime") || "";
    const host = node.querySelector("Computer")?.textContent?.trim() || "";
    const channel = node.querySelector("Channel")?.textContent?.trim() || "";
    const rec = node.querySelector("EventRecordID")?.textContent?.trim() || String(idx);

    const user = get("User") || get("SubjectUserName") || get("TargetUserName") || "";
    const image = get("Image") || get("NewProcessName") || "";
    const cmdline = get("CommandLine") || "";
    const parent = get("ParentImage") || get("ParentProcessName") || "";
    const targetFile = get("TargetFilename") || "";
    const dstIp = get("DestinationIp") || "";
    const dstPort = get("DestinationPort") || "";
    const dnsQuery = get("QueryName") || "";
    const dnsResult = get("QueryResults") || "";
    const grantedAccess = get("GrantedAccess") || "";
    const targetImage = get("TargetImage") || "";
    const srcImage = get("SourceImage") || "";
    const serviceName = get("ServiceName") || "";
    const logonType = get("LogonType") || "";
    const hashes = get("Hashes") || "";

    const severity_info = SEVERITY[eid] || { label:`EID ${eid}`, color:"#6b7280", cat:"other" };

    // Flag detection
    const fullText = [cmdline, targetFile, dnsQuery, image, parent, srcImage].join(" ");
    const foundFlags = FLAGS.filter(f => f.pattern.test(fullText));

    evts.push({
      id: rec, eid, time: timeRaw, host, channel, user, image, cmdline, parent,
      targetFile, dstIp, dstPort, dnsQuery, dnsResult, grantedAccess, targetImage,
      srcImage, serviceName, logonType, hashes, severity_info, foundFlags,
      raw: node.outerHTML,
    });
  });
  return { events: evts, error: null };
}

// ── query engine ──
function runQuery(events, q) {
  if (!q.trim()) return events;
  const parts = q.trim().split(/\s+AND\s+/i);
  return events.filter(ev => {
    return parts.every(part => {
      const m = part.match(/^(\w+)\s*(=|!=|CONTAINS|NOT CONTAINS|STARTSWITH|ENDSWITH|>|<)\s*"?([^"]*)"?$/i);
      if (!m) {
        // free-text search
        const lower = part.toLowerCase();
        return JSON.stringify(ev).toLowerCase().includes(lower);
      }
      const [, field, op, val] = m;
      const fieldMap = {
        eid:"eid", eventid:"eid", id:"eid",
        host:"host", computer:"host", hostname:"host",
        user:"user", username:"user",
        image:"image", process:"image",
        cmdline:"cmdline", commandline:"cmdline", cmd:"cmdline",
        parent:"parent", parentimage:"parent",
        dstip:"dstIp", destinationip:"dstIp", ip:"dstIp",
        dstport:"dstPort", port:"dstPort",
        dns:"dnsQuery", dnsquery:"dnsQuery",
        file:"targetFile", targetfile:"targetFile", filename:"targetFile",
        channel:"channel",
        hashes:"hashes", hash:"hashes",
        access:"grantedAccess", grantedaccess:"grantedAccess",
        servicename:"serviceName",
      };
      const key = fieldMap[field.toLowerCase()];
      if (!key) return JSON.stringify(ev).toLowerCase().includes(val.toLowerCase());
      const evVal = String(ev[key] || "").toLowerCase();
      const cmpVal = val.toLowerCase();
      switch(op.toUpperCase()) {
        case "=":           return evVal === cmpVal;
        case "!=":          return evVal !== cmpVal;
        case "CONTAINS":    return evVal.includes(cmpVal);
        case "NOT CONTAINS":return !evVal.includes(cmpVal);
        case "STARTSWITH":  return evVal.startsWith(cmpVal);
        case "ENDSWITH":    return evVal.endsWith(cmpVal);
        default:            return evVal.includes(cmpVal);
      }
    });
  });
}

const PRESETS = [
  { label:"⚡ WINWORD spawns cmd",  q:`parent CONTAINS "WINWORD" AND eid = "1"` },
  { label:"🌐 C2 Beacon (185.220)",  q:`dstip CONTAINS "185.220" AND eid = "3"` },
  { label:"🔑 LSASS Access",         q:`eid = "10" AND image CONTAINS "lsass"` },
  { label:"💀 LSASS Accessed BY",    q:`eid = "10" AND targetimage CONTAINS "lsass"` },
  { label:"📦 PsExec Drop",          q:`eid = "11" AND file CONTAINS "psexec"` },
  { label:"🔐 PsExec Run",           q:`cmdline CONTAINS "psexec" AND eid = "1"` },
  { label:"🧠 Encoded PowerShell",   q:`cmdline CONTAINS "-Enc" AND eid = "1"` },
  { label:"🕵️ Discovery Commands",  q:`eid = "1" AND user CONTAINS "jmendoza" AND (cmdline CONTAINS "whoami" OR cmdline CONTAINS "net user" OR cmdline CONTAINS "ipconfig" OR cmdline CONTAINS "systeminfo")` },
  { label:"🗂️ Files in Temp",       q:`eid = "11" AND file CONTAINS "Temp"` },
  { label:"🌍 DGA Domains",          q:`eid = "22" AND dns CONTAINS "xk3r9"` },
  { label:"⚙️ Service Install",      q:`eid = "7045"` },
  { label:"🔓 Explicit Cred Logon",  q:`eid = "4648"` },
  { label:"🧹 Attacker Cleanup",     q:`cmdline CONTAINS "del /f" AND user CONTAINS "jmendoza"` },
  { label:"📤 Exfil POST",           q:`cmdline CONTAINS "POST" AND eid = "1"` },
  { label:"🔬 Procdump Execution",   q:`cmdline CONTAINS "lsass" AND eid = "1"` },
  { label:"👤 All jmendoza Events",  q:`user CONTAINS "jmendoza"` },
  { label:"🖥️ WORKSTATION-03 Only", q:`host = "WORKSTATION-03"` },
  { label:"🏴 All Flags",            q:`cmdline CONTAINS "CTF{"` },
];

export default function App() {
  const [rawXml, setRawXml]         = useState(null);
  const [allEvents, setAllEvents]   = useState([]);
  const [filtered, setFiltered]     = useState([]);
  const [query, setQuery]           = useState("");
  const [parseErr, setParseErr]     = useState(null);
  const [loading, setLoading]       = useState(false);
  const [selected, setSelected]     = useState(null);
  const [tab, setTab]               = useState("table");
  const [foundFlags, setFoundFlags] = useState([]);
  const [page, setPage]             = useState(0);
  const [sortField, setSortField]   = useState("time");
  const [sortDir, setSortDir]       = useState("asc");
  const [catFilter, setCatFilter]   = useState("all");
  const fileRef = useRef();
  const PAGE_SIZE = 50;

  const loadXml = useCallback((xml) => {
    setLoading(true);
    setTimeout(() => {
      const result = parseEvents(xml);
      if (result.error) { setParseErr(result.error); setLoading(false); return; }
      setAllEvents(result.events);
      setFiltered(result.events);
      setParseErr(null);
      setPage(0);
      // collect flags already visible
      const flags = new Set();
      result.events.forEach(e => e.foundFlags.forEach(f => flags.add(f.id)));
      setFoundFlags([...flags]);
      setLoading(false);
    }, 80);
  }, []);

  const handleFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => { setRawXml(ev.target.result); loadXml(ev.target.result); };
    reader.readAsText(file);
  };

  const execQuery = useCallback(() => {
    if (!allEvents.length) return;
    let res = runQuery(allEvents, query);
    if (catFilter !== "all") res = res.filter(e => e.severity_info.cat === catFilter);
    res = [...res].sort((a, b) => {
      const av = a[sortField] || ""; const bv = b[sortField] || "";
      return sortDir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    setFiltered(res);
    setPage(0);
  }, [allEvents, query, catFilter, sortField, sortDir]);

  useEffect(() => { execQuery(); }, [catFilter, sortField, sortDir]);

  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);

  // timeline buckets (hourly)
  const timelineBuckets = (() => {
    if (!filtered.length) return [];
    const buckets = {};
    filtered.forEach(e => {
      const d = new Date(e.time);
      if (isNaN(d)) return;
      const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")} ${String(d.getHours()).padStart(2,"0")}:00`;
      buckets[key] = (buckets[key] || 0) + 1;
    });
    return Object.entries(buckets).sort(([a],[b]) => a.localeCompare(b));
  })();
  const maxBucket = Math.max(...timelineBuckets.map(([,v])=>v), 1);

  // stats
  const stats = (() => {
    const eidCount = {};
    const hostCount = {};
    const userCount = {};
    filtered.forEach(e => {
      eidCount[e.eid] = (eidCount[e.eid]||0) + 1;
      hostCount[e.host] = (hostCount[e.host]||0) + 1;
      userCount[e.user] = (userCount[e.user]||0) + 1;
    });
    return { eidCount, hostCount, userCount };
  })();

  const handleSort = (field) => {
    if (sortField === field) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortField(field); setSortDir("asc"); }
  };

  const style = `
${FONTS}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0a0c0f; color: #c9d1d9; font-family: 'IBM Plex Sans', sans-serif; font-size: 13px; }
.mono { font-family: 'JetBrains Mono', monospace; }
.app { display: flex; flex-direction: column; min-height: 100vh; background: #0a0c0f; }

/* HEADER */
.header { background: #0d1117; border-bottom: 1px solid #1e2730; padding: 0 20px; display: flex; align-items: center; gap: 16px; height: 52px; }
.logo { font-family: 'JetBrains Mono', monospace; font-size: 15px; font-weight: 700; color: #58a6ff; letter-spacing: 2px; }
.logo span { color: #f85149; }
.badge { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-size: 11px; color: #7d8590; font-family: 'JetBrains Mono', monospace; }
.flag-bar { margin-left: auto; display: flex; gap: 6px; }
.flag-chip { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-family: 'JetBrains Mono', monospace; font-weight: 700; border: 1px solid; }
.flag-chip.found { background: #0d2b1a; border-color: #238636; color: #3fb950; }
.flag-chip.missing { background: #161b22; border-color: #30363d; color: #484f58; }

/* UPLOAD SCREEN */
.upload-screen { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 20px; }
.upload-box { border: 2px dashed #30363d; border-radius: 12px; padding: 60px 80px; text-align: center; cursor: pointer; transition: border-color .2s, background .2s; }
.upload-box:hover { border-color: #58a6ff; background: #0d1117; }
.upload-title { font-size: 22px; font-weight: 600; color: #e6edf3; margin-bottom: 8px; }
.upload-sub { color: #7d8590; font-size: 13px; }
.upload-hint { color: #484f58; font-size: 12px; font-family: 'JetBrains Mono', monospace; margin-top: 16px; }
.btn-upload { margin-top: 20px; background: #1f6feb; color: #fff; border: none; border-radius: 6px; padding: 10px 24px; font-size: 13px; cursor: pointer; font-family: 'IBM Plex Sans', sans-serif; font-weight: 500; }
.btn-upload:hover { background: #388bfd; }

/* TOOLBAR */
.toolbar { background: #0d1117; border-bottom: 1px solid #1e2730; padding: 10px 16px; display: flex; flex-direction: column; gap: 8px; }
.query-row { display: flex; gap: 8px; align-items: center; }
.query-input { flex: 1; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 8px 12px; color: #e6edf3; font-family: 'JetBrains Mono', monospace; font-size: 12px; outline: none; }
.query-input:focus { border-color: #58a6ff; }
.btn-run { background: #238636; color: #fff; border: none; border-radius: 6px; padding: 8px 18px; font-size: 12px; cursor: pointer; font-weight: 600; white-space: nowrap; }
.btn-run:hover { background: #2ea043; }
.btn-clear { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 8px 14px; font-size: 12px; cursor: pointer; }
.presets { display: flex; gap: 6px; flex-wrap: wrap; }
.preset-btn { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 4px 10px; font-size: 11px; color: #8b949e; cursor: pointer; white-space: nowrap; transition: all .15s; }
.preset-btn:hover { border-color: #58a6ff; color: #58a6ff; background: #0d1f3c; }
.cat-pills { display: flex; gap: 6px; align-items: center; }
.cat-pill { border-radius: 20px; padding: 3px 12px; font-size: 11px; cursor: pointer; border: 1px solid transparent; transition: all .15s; }

/* MAIN */
.main { display: flex; flex: 1; overflow: hidden; }
.sidebar { width: 220px; background: #0d1117; border-right: 1px solid #1e2730; overflow-y: auto; padding: 12px; flex-shrink: 0; }
.sidebar-section { margin-bottom: 16px; }
.sidebar-title { font-size: 10px; font-weight: 600; color: #484f58; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px; }
.stat-row { display: flex; justify-content: space-between; align-items: center; padding: 3px 0; border-bottom: 1px solid #1e2730; }
.stat-label { font-size: 11px; color: #8b949e; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 140px; }
.stat-val { font-size: 11px; font-family: 'JetBrains Mono', monospace; color: #58a6ff; }
.eid-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }

/* CONTENT */
.content { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
.tabs { display: flex; border-bottom: 1px solid #1e2730; background: #0d1117; }
.tab { padding: 8px 20px; font-size: 12px; cursor: pointer; color: #7d8590; border-bottom: 2px solid transparent; transition: all .15s; }
.tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }
.tab-content { flex: 1; overflow: auto; }

/* TABLE */
.tbl { width: 100%; border-collapse: collapse; }
.tbl th { background: #0d1117; padding: 8px 10px; text-align: left; font-size: 10px; font-weight: 600; color: #484f58; letter-spacing: .8px; text-transform: uppercase; border-bottom: 1px solid #1e2730; cursor: pointer; white-space: nowrap; position: sticky; top: 0; z-index: 1; }
.tbl th:hover { color: #8b949e; }
.tbl td { padding: 7px 10px; border-bottom: 1px solid #161b22; font-size: 12px; vertical-align: top; }
.tbl tr { cursor: pointer; transition: background .1s; }
.tbl tr:hover td { background: #161b22; }
.tbl tr.selected td { background: #0d1f3c !important; }
.tbl tr.flag-row td { background: #0d2b1a !important; }
.tbl tr.flag-row:hover td { background: #0f3a20 !important; }
.eid-badge { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 10px; font-family: 'JetBrains Mono', monospace; font-weight: 700; }
.time-cell { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #7d8590; white-space: nowrap; }
.host-cell { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #a5d6ff; }
.user-cell { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #ffa657; }
.cmd-cell { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #d2a8ff; max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.flag-pill { display: inline-block; background: #0d2b1a; border: 1px solid #238636; border-radius: 3px; padding: 1px 6px; font-size: 10px; color: #3fb950; font-family: 'JetBrains Mono', monospace; margin-left: 4px; }

/* DETAIL PANEL */
.detail { background: #0d1117; border-top: 1px solid #1e2730; height: 260px; overflow-y: auto; padding: 12px 16px; }
.detail-title { font-size: 12px; font-weight: 600; color: #e6edf3; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
.detail-grid { display: grid; grid-template-columns: 140px 1fr; gap: 4px 10px; }
.detail-key { font-size: 11px; color: #484f58; font-family: 'JetBrains Mono', monospace; padding: 3px 0; border-bottom: 1px solid #161b22; }
.detail-val { font-size: 11px; color: #c9d1d9; font-family: 'JetBrains Mono', monospace; padding: 3px 0; border-bottom: 1px solid #161b22; word-break: break-all; }
.detail-val.highlight { color: #3fb950; font-weight: 700; }
.detail-val.danger { color: #f85149; }
.detail-val.info { color: #58a6ff; }

/* TIMELINE */
.timeline-wrap { padding: 16px; overflow-y: auto; }
.tl-bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.tl-label { font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #484f58; width: 130px; flex-shrink: 0; }
.tl-bar-bg { flex: 1; background: #161b22; border-radius: 2px; height: 16px; position: relative; }
.tl-bar-fill { height: 100%; border-radius: 2px; transition: width .3s; background: #1f6feb; }
.tl-count { font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #58a6ff; width: 40px; text-align: right; }

/* STATS */
.stats-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; padding: 16px; }
.stat-card { background: #0d1117; border: 1px solid #1e2730; border-radius: 8px; padding: 14px; }
.stat-card-title { font-size: 10px; font-weight: 600; color: #484f58; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 10px; }

/* PAGINATION */
.pagination { display: flex; align-items: center; gap: 8px; padding: 8px 16px; background: #0d1117; border-top: 1px solid #1e2730; font-size: 12px; color: #7d8590; }
.pg-btn { background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 4px 12px; color: #c9d1d9; cursor: pointer; font-size: 11px; }
.pg-btn:disabled { opacity: .3; cursor: default; }

/* LOADING */
.loading { display: flex; align-items: center; justify-content: center; padding: 40px; color: #58a6ff; font-family: 'JetBrains Mono', monospace; font-size: 13px; gap: 10px; }
.spinner { width: 18px; height: 18px; border: 2px solid #1e2730; border-top-color: #58a6ff; border-radius: 50%; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* RESULT COUNT */
.result-count { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #58a6ff; padding: 6px 16px; background: #0d1117; border-bottom: 1px solid #1e2730; }

/* FLAG PANEL */
.flag-panel { padding: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.flag-card { background: #0d1117; border: 1px solid; border-radius: 8px; padding: 14px; }
.flag-card.found { border-color: #238636; }
.flag-card.missing { border-color: #30363d; opacity: .6; }
.flag-card-id { font-family: 'JetBrains Mono', monospace; font-size: 14px; font-weight: 700; margin-bottom: 4px; }
.flag-card-hint { font-size: 12px; color: #7d8590; margin-top: 6px; }
.flag-card-act { font-size: 11px; color: #484f58; margin-top: 4px; }
`;

  // ── render ──
  if (!rawXml && !loading) {
    return (
      <div className="app" style={{fontFamily:"'IBM Plex Sans', sans-serif"}}>
        <style>{style}</style>
        <div className="header">
          <div className="logo">GHOST<span>RELAY</span> SIEM</div>
          <div className="badge">CTF Edition</div>
          <div className="badge">Operation Ghost Relay</div>
        </div>
        <div className="upload-screen">
          <div className="upload-box" onClick={() => fileRef.current.click()}>
            <div className="upload-title">Drop your log file here</div>
            <div className="upload-sub">Import <code>ghost_relay_logs.xml</code> to begin investigation</div>
            <div className="upload-hint">ghost_relay_logs.xml · ~2 MB · 1,558 events</div>
            <button className="btn-upload">Browse File</button>
          </div>
          <input ref={fileRef} type="file" accept=".xml" style={{display:"none"}} onChange={handleFile}/>
          <div style={{color:"#484f58",fontSize:"12px",fontFamily:"JetBrains Mono,monospace",textAlign:"center"}}>
            Supported: Windows Sysmon + Security + System event XML<br/>
            Load the wiki docs page for query reference
          </div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="app">
        <style>{style}</style>
        <div className="header"><div className="logo">GHOST<span>RELAY</span> SIEM</div></div>
        <div className="loading"><div className="spinner"/>Parsing events…</div>
      </div>
    );
  }

  if (parseErr) {
    return (
      <div className="app">
        <style>{style}</style>
        <div className="header"><div className="logo">GHOST<span>RELAY</span> SIEM</div></div>
        <div className="loading" style={{color:"#f85149"}}>{parseErr}</div>
      </div>
    );
  }

  const fmtTime = (t) => {
    try { const d = new Date(t); return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`; }
    catch { return t; }
  };

  return (
    <div className="app">
      <style>{style}</style>

      {/* HEADER */}
      <div className="header">
        <div className="logo">GHOST<span>RELAY</span> SIEM</div>
        <div className="badge">CTF Edition</div>
        <div className="badge mono">{allEvents.length.toLocaleString()} events</div>
        <div className="badge mono">2024-03-11 → 2024-03-13</div>
        <div className="flag-bar">
          {FLAGS.map(f => (
            <div key={f.id} className={`flag-chip ${foundFlags.includes(f.id) ? "found" : "missing"}`}>
              {foundFlags.includes(f.id) ? "🏴 " : "🔒 "}{f.id}
            </div>
          ))}
        </div>
      </div>

      {/* TOOLBAR */}
      <div className="toolbar">
        <div className="query-row">
          <input
            className="query-input mono"
            placeholder='Query: eid = "1" AND cmdline CONTAINS "powershell" AND host = "WORKSTATION-03"'
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === "Enter" && execQuery()}
          />
          <button className="btn-run" onClick={execQuery}>▶ Run</button>
          <button className="btn-clear" onClick={() => { setQuery(""); setCatFilter("all"); setFiltered(allEvents); setPage(0); }}>Clear</button>
          <button className="btn-clear" onClick={() => { setRawXml(null); setAllEvents([]); setFiltered([]); }}>⏏ Eject</button>
        </div>
        <div style={{display:"flex",gap:"12px",alignItems:"center",flexWrap:"wrap"}}>
          <div className="presets">
            {PRESETS.map(p => (
              <button key={p.label} className="preset-btn" onClick={() => { setQuery(p.q); setTimeout(()=>{ const res=runQuery(allEvents,p.q); setFiltered(res); setPage(0); },0); }}>
                {p.label}
              </button>
            ))}
          </div>
        </div>
        <div className="cat-pills">
          <span style={{fontSize:"10px",color:"#484f58",marginRight:"4px"}}>FILTER:</span>
          {["all","process","network","file","auth","system"].map(c => (
            <button key={c} className="cat-pill"
              style={{
                background: catFilter===c ? (CAT_COLORS[c]||"#58a6ff")+"22" : "#161b22",
                borderColor: catFilter===c ? (CAT_COLORS[c]||"#58a6ff") : "#30363d",
                color: catFilter===c ? (CAT_COLORS[c]||"#58a6ff") : "#7d8590",
              }}
              onClick={() => setCatFilter(c)}
            >{c.toUpperCase()}</button>
          ))}
        </div>
      </div>

      {/* MAIN */}
      <div className="main">
        {/* SIDEBAR */}
        <div className="sidebar">
          <div className="sidebar-section">
            <div className="sidebar-title">Event IDs</div>
            {Object.entries(stats.eidCount).sort(([,a],[,b])=>b-a).slice(0,12).map(([eid,cnt]) => {
              const si = SEVERITY[eid] || { color:"#6b7280", label:`EID ${eid}` };
              return (
                <div key={eid} className="stat-row" style={{cursor:"pointer"}} onClick={() => { const q=`eid = "${eid}"`; setQuery(q); const r=runQuery(allEvents,q); setFiltered(r); setPage(0); }}>
                  <span className="stat-label"><span className="eid-dot" style={{background:si.color}}/>{eid} {si.label}</span>
                  <span className="stat-val">{cnt}</span>
                </div>
              );
            })}
          </div>
          <div className="sidebar-section">
            <div className="sidebar-title">Hosts</div>
            {Object.entries(stats.hostCount).sort(([,a],[,b])=>b-a).map(([h,c]) => (
              <div key={h} className="stat-row" style={{cursor:"pointer"}} onClick={() => { const q=`host = "${h}"`; setQuery(q); const r=runQuery(allEvents,q); setFiltered(r); setPage(0); }}>
                <span className="stat-label mono" style={{fontSize:"10px"}}>{h}</span>
                <span className="stat-val">{c}</span>
              </div>
            ))}
          </div>
          <div className="sidebar-section">
            <div className="sidebar-title">Users (top)</div>
            {Object.entries(stats.userCount).sort(([,a],[,b])=>b-a).slice(0,8).map(([u,c]) => (
              <div key={u} className="stat-row" style={{cursor:"pointer"}} onClick={() => { const q=`user CONTAINS "${u.split("\\").pop()}"`; setQuery(q); const r=runQuery(allEvents,q); setFiltered(r); setPage(0); }}>
                <span className="stat-label" style={{color:"#ffa657",fontSize:"10px"}}>{u.split("\\").pop()||u}</span>
                <span className="stat-val">{c}</span>
              </div>
            ))}
          </div>
        </div>

        {/* CONTENT */}
        <div className="content">
          <div className="tabs">
            {["table","timeline","stats","flags"].map(t2 => (
              <div key={t2} className={`tab ${tab===t2?"active":""}`} onClick={()=>setTab(t2)}>
                {t2==="table"?"📋 Events":t2==="timeline"?"📈 Timeline":t2==="stats"?"📊 Stats":"🏴 Flags"}
              </div>
            ))}
          </div>

          <div className="result-count">
            {filtered.length.toLocaleString()} results · showing {page*PAGE_SIZE+1}–{Math.min((page+1)*PAGE_SIZE,filtered.length)} · page {page+1}/{totalPages||1}
          </div>

          <div className="tab-content">
            {tab === "table" && (
              <>
                <table className="tbl">
                  <thead>
                    <tr>
                      {[["time","Time"],["eid","EID"],["host","Host"],["user","User"],["image","Image / Process"],["cmdline","CommandLine / Detail"]].map(([f,l]) => (
                        <th key={f} onClick={() => handleSort(f)}>{l} {sortField===f?(sortDir==="asc"?"▲":"▼"):""}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {paged.map(ev => {
                      const si = ev.severity_info;
                      const hasFlag = ev.foundFlags.length > 0;
                      const isSelected = selected?.id === ev.id;
                      let detail = ev.cmdline || ev.targetFile || ev.dnsQuery ||
                        (ev.dstIp ? `→ ${ev.dstIp}:${ev.dstPort}` : "") ||
                        (ev.targetImage ? `target: ${ev.targetImage}` : "") ||
                        ev.serviceName || "";
                      return (
                        <tr key={ev.id} className={`${hasFlag?"flag-row":""} ${isSelected?"selected":""}`}
                          onClick={() => setSelected(isSelected ? null : ev)}>
                          <td className="time-cell">{fmtTime(ev.time)}</td>
                          <td>
                            <span className="eid-badge" style={{background:si.color+"22",color:si.color,border:`1px solid ${si.color}44`}}>{ev.eid}</span>
                            {hasFlag && ev.foundFlags.map(f=><span key={f.id} className="flag-pill">🏴</span>)}
                          </td>
                          <td className="host-cell">{ev.host}</td>
                          <td className="user-cell">{(ev.user||"").split("\\").pop()}</td>
                          <td className="cmd-cell" style={{color:"#a5d6ff"}}>{ev.image.split("\\").pop()}</td>
                          <td className="cmd-cell">{detail}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                {selected && (
                  <div className="detail">
                    <div className="detail-title">
                      <span className="eid-badge" style={{background:selected.severity_info.color+"22",color:selected.severity_info.color,border:`1px solid ${selected.severity_info.color}44`,fontSize:"12px"}}>{selected.eid} {selected.severity_info.label}</span>
                      {selected.host} · {fmtTime(selected.time)}
                      {selected.foundFlags.map(f => <span key={f.id} className="flag-pill" style={{fontSize:"12px"}}>🏴 {f.id}</span>)}
                      <button style={{marginLeft:"auto",background:"none",border:"none",color:"#484f58",cursor:"pointer",fontSize:"16px"}} onClick={() => setSelected(null)}>✕</button>
                    </div>
                    <div className="detail-grid">
                      {[
                        ["EventID",        selected.eid],
                        ["Time",           selected.time],
                        ["Host",           selected.host],
                        ["Channel",        selected.channel],
                        ["User",           selected.user,       "info"],
                        ["Image",          selected.image,      "info"],
                        ["CommandLine",    selected.cmdline,    selected.cmdline?.includes("CTF{")?"highlight":""],
                        ["ParentImage",    selected.parent],
                        ["TargetFilename", selected.targetFile, selected.targetFile?.includes("CTF{")?"highlight":""],
                        ["DestIP:Port",    selected.dstIp ? `${selected.dstIp}:${selected.dstPort}` : "", selected.dstIp==="185.220.101.47"?"danger":""],
                        ["DNS Query",      selected.dnsQuery],
                        ["DNS Result",     selected.dnsResult],
                        ["GrantedAccess",  selected.grantedAccess, selected.grantedAccess==="0x1FFFFF"?"danger":""],
                        ["TargetImage",    selected.targetImage],
                        ["Hashes",         selected.hashes],
                        ["ServiceName",    selected.serviceName],
                        ["LogonType",      selected.logonType],
                      ].filter(([,v]) => v).map(([k,v,cls]) => (
                        <>
                          <div className="detail-key">{k}</div>
                          <div className={`detail-val ${cls||""}`}>{v}</div>
                        </>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}

            {tab === "timeline" && (
              <div className="timeline-wrap">
                <div style={{marginBottom:"16px",color:"#7d8590",fontSize:"12px"}}>
                  Activity histogram — {filtered.length} events across {timelineBuckets.length} hours
                </div>
                {timelineBuckets.map(([label, count]) => (
                  <div key={label} className="tl-bar-row">
                    <div className="tl-label">{label}</div>
                    <div className="tl-bar-bg">
                      <div className="tl-bar-fill" style={{
                        width: `${(count/maxBucket)*100}%`,
                        background: count > maxBucket*0.5 ? "#f85149" : count > maxBucket*0.25 ? "#f59e0b" : "#1f6feb"
                      }}/>
                    </div>
                    <div className="tl-count">{count}</div>
                  </div>
                ))}
              </div>
            )}

            {tab === "stats" && (
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-card-title">Event ID Breakdown</div>
                  {Object.entries(stats.eidCount).sort(([,a],[,b])=>b-a).map(([eid,cnt]) => {
                    const si = SEVERITY[eid]||{color:"#6b7280",label:`EID ${eid}`};
                    const pct = (cnt/filtered.length*100).toFixed(1);
                    return (
                      <div key={eid} style={{marginBottom:"6px"}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:"2px"}}>
                          <span style={{fontSize:"11px",color:si.color,fontFamily:"JetBrains Mono,monospace"}}>{eid} {si.label}</span>
                          <span style={{fontSize:"11px",color:"#58a6ff",fontFamily:"JetBrains Mono,monospace"}}>{cnt}</span>
                        </div>
                        <div style={{background:"#161b22",borderRadius:"2px",height:"6px"}}>
                          <div style={{width:`${pct}%`,background:si.color,height:"100%",borderRadius:"2px"}}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="stat-card">
                  <div className="stat-card-title">Events per Host</div>
                  {Object.entries(stats.hostCount).sort(([,a],[,b])=>b-a).map(([h,cnt]) => {
                    const pct = (cnt/filtered.length*100).toFixed(1);
                    return (
                      <div key={h} style={{marginBottom:"6px"}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:"2px"}}>
                          <span style={{fontSize:"11px",color:"#a5d6ff",fontFamily:"JetBrains Mono,monospace"}}>{h}</span>
                          <span style={{fontSize:"11px",color:"#58a6ff",fontFamily:"JetBrains Mono,monospace"}}>{cnt}</span>
                        </div>
                        <div style={{background:"#161b22",borderRadius:"2px",height:"6px"}}>
                          <div style={{width:`${pct}%`,background:"#3b82f6",height:"100%",borderRadius:"2px"}}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="stat-card">
                  <div className="stat-card-title">Events per User</div>
                  {Object.entries(stats.userCount).sort(([,a],[,b])=>b-a).slice(0,10).map(([u,cnt]) => {
                    const pct = (cnt/filtered.length*100).toFixed(1);
                    return (
                      <div key={u} style={{marginBottom:"6px"}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:"2px"}}>
                          <span style={{fontSize:"11px",color:"#ffa657",fontFamily:"JetBrains Mono,monospace"}}>{(u||"").split("\\").pop()||u||"(none)"}</span>
                          <span style={{fontSize:"11px",color:"#58a6ff",fontFamily:"JetBrains Mono,monospace"}}>{cnt}</span>
                        </div>
                        <div style={{background:"#161b22",borderRadius:"2px",height:"6px"}}>
                          <div style={{width:`${pct}%`,background:"#f97316",height:"100%",borderRadius:"2px"}}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {tab === "flags" && (
              <div className="flag-panel">
                {FLAGS.map(f => {
                  const isFound = foundFlags.includes(f.id);
                  return (
                    <div key={f.id} className={`flag-card ${isFound?"found":"missing"}`}>
                      <div className="flag-card-id" style={{color:isFound?"#3fb950":"#484f58"}}>{isFound?"🏴":"🔒"} {f.id}</div>
                      <div style={{fontSize:"12px",color:isFound?"#3fb950":"#484f58",fontFamily:"JetBrains Mono,monospace",marginTop:"4px"}}>
                        {isFound ? "✓ CAPTURED" : "NOT YET FOUND"}
                      </div>
                      <div className="flag-card-act" style={{color:"#7d8590"}}>Act {f.act}</div>
                      <div className="flag-card-hint">💡 {f.hint}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* PAGINATION */}
          {tab === "table" && (
            <div className="pagination">
              <button className="pg-btn" disabled={page===0} onClick={()=>setPage(0)}>«</button>
              <button className="pg-btn" disabled={page===0} onClick={()=>setPage(p=>p-1)}>‹</button>
              <span>Page {page+1} of {totalPages||1}</span>
              <button className="pg-btn" disabled={page>=totalPages-1} onClick={()=>setPage(p=>p+1)}>›</button>
              <button className="pg-btn" disabled={page>=totalPages-1} onClick={()=>setPage(totalPages-1)}>»</button>
              <span style={{marginLeft:"auto",color:"#484f58"}}>50 events/page</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
