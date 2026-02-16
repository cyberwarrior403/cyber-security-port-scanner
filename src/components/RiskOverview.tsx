import { ScanResult } from "@/lib/scan-data";
import { ShieldAlert, ShieldCheck, Activity, Target } from "lucide-react";

interface RiskOverviewProps {
  results: ScanResult[];
  target: string;
}

const RiskOverview = ({ results, target }: RiskOverviewProps) => {
  const critical = results.filter((r) => r.risk === "critical").length;
  const high = results.filter((r) => r.risk === "high").length;
  const medium = results.filter((r) => r.risk === "medium").length;
  const low = results.filter((r) => r.risk === "low").length;

  // Compute a normalized score based on how many high/critical vs low findings exist.
  // This avoids always returning 100 and better reflects the mix of ports.
  const severityWeight: Record<ScanResult["risk"], number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };

  const totalPorts = results.length;
  const maxScore = totalPorts * severityWeight.critical;
  const totalScore = results.reduce(
    (sum, r) => sum + severityWeight[r.risk],
    0
  );

  const overallScore =
    totalPorts === 0
      ? 0
      : Math.round((totalScore / maxScore) * 100);

  const overallRisk =
    overallScore >= 75
      ? "Critical"
      : overallScore >= 50
      ? "High"
      : overallScore >= 25
      ? "Medium"
      : "Low";

  const riskColorClass =
    overallRisk === "Critical"
      ? "text-destructive"
      : overallRisk === "High"
      ? "text-warning"
      : overallRisk === "Medium"
      ? "text-primary"
      : "text-accent";

  const stats = [
    { label: "Critical", count: critical, color: "bg-destructive", icon: ShieldAlert },
    { label: "High", count: high, color: "bg-warning", icon: Activity },
    { label: "Medium", count: medium, color: "bg-primary", icon: Target },
    { label: "Low", count: low, color: "bg-accent", icon: ShieldCheck },
  ];

  return (
    <div className="space-y-4">
      {/* Risk Score */}
      <div className="bg-card border border-border rounded-lg p-6 text-center border-glow">
        <p className="text-xs text-muted-foreground font-mono mb-1">TARGET</p>
        <p className="text-sm font-mono text-primary text-glow mb-4">{target}</p>
        
        <div className="relative w-32 h-32 mx-auto mb-4">
          <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
            <circle cx="50" cy="50" r="42" fill="none" stroke="hsl(var(--secondary))" strokeWidth="6" />
            <circle
              cx="50" cy="50" r="42" fill="none"
              stroke="currentColor"
              strokeWidth="6"
              strokeDasharray={`${overallScore * 2.64} ${264 - overallScore * 2.64}`}
              strokeLinecap="round"
              className={riskColorClass}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-3xl font-bold font-mono ${riskColorClass}`}>{overallScore}</span>
            <span className="text-xs text-muted-foreground">/ 100</span>
          </div>
        </div>

        <p className={`text-sm font-semibold uppercase ${riskColorClass}`}>
          {overallRisk} Risk
        </p>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-3">
        {stats.map((stat) => (
          <div key={stat.label} className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-2 h-2 rounded-full ${stat.color}`} />
              <span className="text-xs text-muted-foreground">{stat.label}</span>
            </div>
            <p className="text-2xl font-bold font-mono text-foreground">{stat.count}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RiskOverview;
