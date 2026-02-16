export interface ScanResult {
  port: number;
  service: string;
  version: string;
  state: "open" | "closed" | "filtered";
  risk: "critical" | "high" | "medium" | "low";
  attack: string;
  recommendation: string;
}

export const mockScanResults: ScanResult[] = [
  { port: 22, service: "SSH", version: "OpenSSH 7.6", state: "open", risk: "medium", attack: "SSH Brute Force, Key Exploitation", recommendation: "Use key-based auth, disable root login" },
  { port: 80, service: "HTTP", version: "Apache 2.4.29", state: "open", risk: "high", attack: "XSS, SQL Injection, Directory Traversal", recommendation: "Enable HTTPS, update to latest version" },
  { port: 443, service: "HTTPS", version: "Nginx 1.18", state: "open", risk: "low", attack: "SSL/TLS Downgrade", recommendation: "Enforce TLS 1.3, HSTS headers" },
  { port: 3306, service: "MySQL", version: "MySQL 5.7.31", state: "open", risk: "critical", attack: "SQL Injection, Data Exfiltration", recommendation: "Restrict to localhost, use firewall rules" },
  { port: 21, service: "FTP", version: "vsftpd 3.0.3", state: "open", risk: "critical", attack: "Anonymous Login, Data Interception", recommendation: "Disable FTP, use SFTP instead" },
  { port: 8080, service: "HTTP-Proxy", version: "Squid 4.6", state: "open", risk: "high", attack: "Proxy Abuse, Cache Poisoning", recommendation: "Restrict access, enable authentication" },
  { port: 25, service: "SMTP", version: "Postfix 3.3", state: "open", risk: "medium", attack: "Email Spoofing, Open Relay", recommendation: "Configure SPF/DKIM, restrict relay" },
  { port: 53, service: "DNS", version: "BIND 9.11", state: "open", risk: "medium", attack: "DNS Amplification, Zone Transfer", recommendation: "Restrict zone transfers, enable DNSSEC" },
];

export const getRiskColor = (risk: ScanResult["risk"]) => {
  switch (risk) {
    case "critical": return "text-destructive";
    case "high": return "text-warning";
    case "medium": return "text-primary";
    case "low": return "text-accent";
  }
};

export const getRiskBg = (risk: ScanResult["risk"]) => {
  switch (risk) {
    case "critical": return "bg-destructive/20 border-destructive/30";
    case "high": return "bg-warning/20 border-warning/30";
    case "medium": return "bg-primary/20 border-primary/30";
    case "low": return "bg-accent/20 border-accent/30";
  }
};
