import { ScanResult, getRiskColor, getRiskBg } from "@/lib/scan-data";
import { Server, AlertTriangle, Shield, ChevronRight } from "lucide-react";
import { useState } from "react";

interface PortTableProps {
  results: ScanResult[];
}

const PortTable = ({ results }: PortTableProps) => {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-5 py-3 border-b border-border bg-secondary/30">
        <Server className="w-4 h-4 text-primary" />
        <span className="font-semibold text-sm">Detected Services</span>
        <span className="ml-auto text-xs text-muted-foreground font-mono">
          {results.length} ports open
        </span>
      </div>

      <div className="divide-y divide-border">
        {results.map((result) => (
          <div key={result.port}>
            <button
              onClick={() => setExpanded(expanded === result.port ? null : result.port)}
              className="w-full flex items-center gap-4 px-5 py-3 hover:bg-secondary/20 transition-colors text-left"
            >
              <span className="font-mono text-sm text-primary w-16">:{result.port}</span>
              <span className="text-sm text-foreground flex-1">{result.service}</span>
              <span className="text-xs text-muted-foreground font-mono hidden sm:block">{result.version}</span>
              <span className={`text-xs font-semibold uppercase px-2 py-0.5 rounded border ${getRiskBg(result.risk)} ${getRiskColor(result.risk)}`}>
                {result.risk}
              </span>
              <ChevronRight className={`w-4 h-4 text-muted-foreground transition-transform ${expanded === result.port ? "rotate-90" : ""}`} />
            </button>

            {expanded === result.port && (
              <div className="px-5 pb-4 pt-1 space-y-3 animate-fade-in-up bg-secondary/10">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-warning mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Possible Attacks</p>
                    <p className="text-sm text-foreground">{result.attack}</p>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <Shield className="w-4 h-4 text-accent mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Recommendation</p>
                    <p className="text-sm text-foreground">{result.recommendation}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default PortTable;
