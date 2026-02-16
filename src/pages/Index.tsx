import { useState, useCallback, useEffect } from "react";
import ScannerInput from "@/components/ScannerInput";
import ScanProgress from "@/components/ScanProgress";
import PortTable from "@/components/PortTable";
import RiskOverview from "@/components/RiskOverview";
import type { ScanResult } from "@/lib/scan-data";
import { RotateCcw, Shield } from "lucide-react";

type Phase = "input" | "scanning" | "results";

const Index = () => {
  const [phase, setPhase] = useState<Phase>("input");
  const [target, setTarget] = useState("");
  const [results, setResults] = useState<ScanResult[] | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [uiDone, setUiDone] = useState(false);
  const [backendDone, setBackendDone] = useState(false);

  const runScan = useCallback(async (t: string) => {
    try {
      const res = await fetch("http://localhost:3001/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ target: t }),
      });

      const data = await res.json().catch(() => null);

      if (!res.ok) {
        throw new Error(data?.error || "Scan failed. Please try again.");
      }

      setResults(data?.results ?? []);
      setScanError(null);
    } catch (err: any) {
      console.error(err);
      setResults(null);
      setScanError(err?.message || "Scan failed. Please try again.");
    } finally {
      setBackendDone(true);
    }
  }, []);

  const handleScan = (t: string) => {
    setTarget(t);
    setResults(null);
    setScanError(null);
    setUiDone(false);
    setBackendDone(false);
    setPhase("scanning");
    void runScan(t);
  };

  const handleComplete = useCallback(() => {
    setUiDone(true);
  }, []);

  useEffect(() => {
    if (phase === "scanning" && uiDone && backendDone) {
      setPhase("results");
    }
  }, [phase, uiDone, backendDone]);

  const handleReset = () => {
    setPhase("input");
    setTarget("");
    setResults(null);
    setScanError(null);
    setUiDone(false);
    setBackendDone(false);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container max-w-6xl flex items-center justify-between py-3 px-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <span className="font-bold text-sm">VulnScanner</span>
            <span className="text-xs text-muted-foreground font-mono ml-2">v1.0</span>
          </div>
          {phase === "results" && (
            <button
              onClick={handleReset}
              className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors font-mono"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              New Scan
            </button>
          )}
        </div>
      </header>

      <main className="container max-w-6xl px-4">
        {phase === "input" && <ScannerInput onScan={handleScan} isScanning={false} />}

        {phase === "scanning" && (
          <ScanProgress target={target} onComplete={handleComplete} />
        )}

        {phase === "results" && (
          <div className="py-8 animate-fade-in-up">
            {scanError ? (
              <p className="text-center text-destructive text-sm font-mono">
                {scanError}
              </p>
            ) : results && results.length > 0 ? (
              <>
                <div className="flex flex-col lg:flex-row gap-6">
                  <div className="lg:w-72 shrink-0">
                    <RiskOverview results={results} target={target} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <PortTable results={results} />
                  </div>
                </div>

                {/* Disclaimer */}
                <p className="text-center text-xs text-muted-foreground/40 font-mono mt-8">
                  ⚠ Real scan via Shodan/InternetDB — open ports and services from Shodan&apos;s database
                </p>
              </>
            ) : (
              <p className="text-center text-sm text-muted-foreground font-mono">
                No open ports detected on this target.
              </p>
            )}
          </div>
        )}
      </main>
    </div>
  );
};

export default Index;
