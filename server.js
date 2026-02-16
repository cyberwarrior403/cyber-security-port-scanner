import "dotenv/config";
import dns from "dns/promises";
import express from "express";
import cors from "cors";
import axios from "axios";

// Simple helper to validate targets on the server side as well.
const ipv4Regex =
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

const urlRegex =
  /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[^\s]*)?$/i;

const isValidTarget = (value) =>
  ipv4Regex.test(value) || urlRegex.test(value);

const app = express();
const PORT = process.env.PORT || 3001;

// Shodan API configuration (free tier: https://account.shodan.io/)
const SHODAN_API_KEY = process.env.SHODAN_API_KEY || "";
const isShodanKeyConfigured = () =>
  SHODAN_API_KEY && SHODAN_API_KEY !== "your_shodan_api_key_here";

if (isShodanKeyConfigured()) {
  console.log("[Shodan] API key configured. IP lookups will use Shodan.");
} else {
  console.log("[Shodan] No API key. IP lookups will use InternetDB (free, no key).");
}

// Port-to-finding mapping for Shodan/InternetDB results
const PORT_FINDINGS = {
  21: { service: "FTP", risk: "critical", attack: "Anonymous login, credential theft", recommendation: "Use SFTP, restrict access" },
  22: { service: "SSH", risk: "medium", attack: "Brute force, key exploitation", recommendation: "Use key-based auth, disable root login" },
  23: { service: "Telnet", risk: "critical", attack: "Plaintext credentials, takeover", recommendation: "Disable Telnet, use SSH" },
  25: { service: "SMTP", risk: "medium", attack: "Email spoofing, open relay", recommendation: "Configure SPF/DKIM, restrict relay" },
  53: { service: "DNS", risk: "medium", attack: "DNS amplification, zone transfer", recommendation: "Restrict zone transfers, DNSSEC" },
  80: { service: "HTTP", risk: "high", attack: "Plaintext traffic, XSS, injection", recommendation: "Enable HTTPS, security headers" },
  110: { service: "POP3", risk: "medium", attack: "Credential interception", recommendation: "Use POP3S, restrict access" },
  143: { service: "IMAP", risk: "medium", attack: "Credential interception", recommendation: "Use IMAPS, restrict access" },
  443: { service: "HTTPS", risk: "low", attack: "SSL/TLS issues", recommendation: "Keep TLS updated, strong ciphers" },
  445: { service: "SMB", risk: "critical", attack: "EternalBlue, credential theft", recommendation: "Disable SMBv1, restrict to VPN" },
  993: { service: "IMAPS", risk: "low", attack: "SSL issues", recommendation: "Keep TLS updated" },
  995: { service: "POP3S", risk: "low", attack: "SSL issues", recommendation: "Keep TLS updated" },
  1433: { service: "MSSQL", risk: "critical", attack: "SQL injection, data exfiltration", recommendation: "Firewall restrict, strong auth" },
  3306: { service: "MySQL", risk: "critical", attack: "SQL injection, data exfiltration", recommendation: "Restrict to localhost, firewall" },
  3389: { service: "RDP", risk: "high", attack: "Brute force, credential theft", recommendation: "Use VPN, strong passwords" },
  5432: { service: "PostgreSQL", risk: "critical", attack: "SQL injection, data exfiltration", recommendation: "Restrict access, strong auth" },
  5900: { service: "VNC", risk: "critical", attack: "Unauthorized access, screen capture", recommendation: "Use VPN, disable if unused" },
  8080: { service: "HTTP-Proxy", risk: "high", attack: "Proxy abuse, cache poisoning", recommendation: "Restrict access, authentication" },
  27017: { service: "MongoDB", risk: "critical", attack: "Unauthenticated access, data theft", recommendation: "Enable auth, restrict to localhost" },
};

function getPortFinding(port, product = "") {
  const known = PORT_FINDINGS[port];
  if (known) return { ...known, version: product };
  return {
    service: `Port ${port}`,
    version: product,
    risk: "medium",
    attack: "Unknown service - verify and secure",
    recommendation: "Identify service, apply least privilege",
  };
}

async function resolveToIp(target) {
  if (ipv4Regex.test(target)) return target;
  const hostname = target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  const addrs = await dns.resolve4(hostname);
  return addrs?.[0] || null;
}

async function fetchShodanHost(ip) {
  const res = await axios.get(
    `https://api.shodan.io/shodan/host/${ip}`,
    {
      params: { key: SHODAN_API_KEY },
      timeout: 15000,
      validateStatus: (status) => status < 500, // Don't throw on 404
    }
  );
  if (res.status === 404) return null;
  if (res.status !== 200) throw new Error(res.data?.error || `Shodan returned ${res.status}`);
  return res.data;
}

async function fetchInternetDB(ip) {
  const res = await axios.get(
    `https://internetdb.shodan.io/${ip}`,
    {
      timeout: 10000,
      validateStatus: (status) => status < 500,
    }
  );
  if (res.status === 404) return null;
  if (res.status !== 200) throw new Error(`InternetDB returned ${res.status}`);
  return res.data;
}

function mapShodanToResults(data) {
  const results = [];
  const portMap = new Map();
  for (const item of data?.data || []) {
    const port = item.port;
    if (!portMap.has(port)) {
      portMap.set(port, item);
    }
  }
  const vulns = data?.vulns ? Object.keys(data.vulns) : [];
  const ports = data?.ports || Array.from(portMap.keys());
  for (const port of ports) {
    const item = portMap.get(port) || {};
    const product = item.product || item.version || item._shodan?.module || "";
    const finding = getPortFinding(port, product);
    results.push({
      port,
      service: finding.service,
      version: finding.version,
      state: "open",
      risk: vulns.length ? "high" : finding.risk,
      attack: vulns.length ? `Known CVEs: ${vulns.slice(0, 8).join(", ")}` : finding.attack,
      recommendation: finding.recommendation,
    });
  }
  return results;
}

function mapInternetDBToResults(data) {
  const results = [];
  const ports = data?.ports || [];
  const vulns = (data?.vulns || []).map((v) => v.split("-")[1] || v);
  const hasVulns = vulns.length > 0;
  for (const port of ports) {
    const finding = getPortFinding(port, "");
    results.push({
      port,
      service: finding.service,
      version: finding.version,
      state: "open",
      risk: hasVulns ? "high" : finding.risk,
      attack: hasVulns ? `Known CVEs: ${vulns.slice(0, 5).join(", ")}` : finding.attack,
      recommendation: finding.recommendation,
    });
  }
  return results;
}

app.use(cors());
app.use(express.json());

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * POST /api/scan
 * Body: { target: string }
 *
 * Uses Shodan or InternetDB for IP lookups. Falls back to demo results
 * when no data is available.
 */
app.post("/api/scan", async (req, res) => {
  const { target } = req.body || {};

  if (!target || typeof target !== "string" || !isValidTarget(target.trim())) {
    return res.status(400).json({ error: "Invalid IP address or URL." });
  }

  const safeTarget = target.trim();

  // Resolve target to IP for Shodan/InternetDB (they only accept IPs)
  let resolvedIp = null;
  try {
    resolvedIp = await resolveToIp(safeTarget);
  } catch (err) {
    console.warn("[Scan] Could not resolve target to IP:", err?.message);
  }

  // Real scan: Shodan (if key) or InternetDB - both use Shodan's database
  if (resolvedIp) {
    let results = [];
    let source = null;

    // Try Shodan first (more detailed, requires API key)
    if (isShodanKeyConfigured()) {
      try {
        const shodanData = await fetchShodanHost(resolvedIp);
        if (shodanData) {
          results = mapShodanToResults(shodanData);
          if (results.length > 0) source = "shodan";
        }
      } catch (err) {
        console.warn("[Shodan] Lookup failed:", err?.message);
      }
    }

    // Fallback to InternetDB (free, no key) if Shodan had no data
    if (!source) {
      try {
        const internetDbData = await fetchInternetDB(resolvedIp);
        if (internetDbData) {
          results = mapInternetDBToResults(internetDbData);
          if (results.length > 0) source = "internetdb";
        }
      } catch (err) {
        console.warn("[InternetDB] Lookup failed:", err?.message);
      }
    }

    if (source && results.length > 0) {
      return res.json({ results, source, realScan: true });
    }
  }

  // No real data
  const errorMsg = !resolvedIp
    ? "Could not resolve target to IP address. Check the URL or try an IP like 8.8.8.8."
    : "No scan data found for this target. Shodan/InternetDB have no records. Try 8.8.8.8, 1.1.1.1, or scanme.nmap.org.";
  return res.status(404).json({
    error: errorMsg,
    results: [],
  });
});

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Scanner API listening on http://localhost:${PORT}`);
});
