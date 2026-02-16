import { useState } from "react";
import { Shield, Search, AlertTriangle } from "lucide-react";

interface ScannerInputProps {
  onScan: (target: string) => void;
  isScanning: boolean;
}

// Basic validators for IPv4 and URLs.
// This keeps validation on the frontend only (no real network scan is performed).
const ipv4Regex =
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

const urlRegex =
  /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[^\s]*)?$/i;

const isValidTarget = (value: string) =>
  ipv4Regex.test(value) || urlRegex.test(value);

const ScannerInput = ({ onScan, isScanning }: ScannerInputProps) => {
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const value = target.trim();

    if (!value) return;

    if (!isValidTarget(value)) {
      setError("Invalid IP address or URL. Please enter a valid target.");
      return;
    }

    setError(null);
    onScan(value);
  };

  return (
    <div className="relative">
      {/* Background grid effect */}
      <div className="absolute inset-0 opacity-5" style={{
        backgroundImage: "linear-gradient(hsl(185 100% 50% / 0.3) 1px, transparent 1px), linear-gradient(90deg, hsl(185 100% 50% / 0.3) 1px, transparent 1px)",
        backgroundSize: "40px 40px"
      }} />
      
      <div className="relative text-center py-16 px-4">
        <div className="flex items-center justify-center gap-3 mb-6">
          <Shield className="w-10 h-10 text-primary animate-pulse-glow" />
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-foreground">
            Vuln<span className="text-primary text-glow">Scanner</span>
          </h1>
        </div>
        
        <p className="text-muted-foreground text-lg mb-2 max-w-xl mx-auto">
          Intelligent Vulnerability Assessment System
        </p>
        <p className="text-muted-foreground/60 text-sm mb-10 max-w-lg mx-auto font-mono">
          Port Scanning • Service Detection • Attack Mapping
        </p>

        <form onSubmit={handleSubmit} className="max-w-2xl mx-auto">
          <div className="relative group">
            <div className="absolute -inset-0.5 bg-primary/20 rounded-lg blur opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity duration-500" />
            <div className="relative flex items-center bg-card border border-border rounded-lg overflow-hidden group-focus-within:border-glow transition-all duration-300">
              <Search className="w-5 h-5 text-muted-foreground ml-4 shrink-0" />
              <input
                type="text"
                value={target}
                onChange={(e) => {
                  setTarget(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="Enter IP address or URL (e.g., 192.168.1.10 or example.com)"
                className="flex-1 bg-transparent px-4 py-4 text-foreground font-mono text-sm placeholder:text-muted-foreground/50 focus:outline-none"
                disabled={isScanning}
              />
              <button
                type="submit"
                disabled={isScanning || !target.trim()}
                className="px-6 py-4 bg-primary text-primary-foreground font-semibold text-sm hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shrink-0"
              >
                {isScanning ? "Scanning..." : "Scan Target"}
              </button>
            </div>
          </div>
        </form>

        {error && (
          <p className="mt-3 text-xs text-destructive font-mono">
            {error}
          </p>
        )}

        <div className="flex items-center justify-center gap-2 mt-6 text-muted-foreground/40 text-xs font-mono">
          <AlertTriangle className="w-3 h-3" />
          <span>For educational purposes only — no real attacks are performed</span>
        </div>
      </div>
    </div>
  );
};

export default ScannerInput;
