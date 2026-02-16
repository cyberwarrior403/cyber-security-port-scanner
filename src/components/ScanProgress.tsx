import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

interface ScanProgressProps {
  target: string;
  onComplete: () => void;
}

const scanSteps = [
  "Resolving target hostname...",
  "Initiating TCP SYN scan...",
  "Scanning common ports (1-1024)...",
  "Detecting service versions...",
  "Mapping attack vectors...",
  "Calculating risk assessment...",
  "Generating report...",
];

const ScanProgress = ({ target, onComplete }: ScanProgressProps) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const stepInterval = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= scanSteps.length - 1) {
          clearInterval(stepInterval);
          setTimeout(onComplete, 600);
          return prev;
        }
        return prev + 1;
      });
    }, 600);

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          return 100;
        }
        return prev + 2;
      });
    }, 80);

    return () => {
      clearInterval(stepInterval);
      clearInterval(progressInterval);
    };
  }, [onComplete]);

  return (
    <div className="max-w-2xl mx-auto px-4 py-12">
      <div className="bg-card border border-border rounded-lg p-8 border-glow">
        <div className="flex items-center gap-3 mb-6">
          <Loader2 className="w-5 h-5 text-primary animate-spin" />
          <span className="text-primary font-mono text-sm text-glow">
            Scanning {target}
          </span>
        </div>

        {/* Progress bar */}
        <div className="relative h-1.5 bg-secondary rounded-full mb-8 overflow-hidden">
          <div
            className="absolute inset-y-0 left-0 bg-primary rounded-full transition-all duration-200"
            style={{ width: `${progress}%` }}
          />
          <div className="absolute inset-0 animate-scan-line bg-gradient-to-b from-transparent via-primary/40 to-transparent" />
        </div>

        {/* Terminal output */}
        <div className="font-mono text-xs space-y-1.5">
          {scanSteps.slice(0, currentStep + 1).map((step, i) => (
            <div
              key={i}
              className="flex items-center gap-2 animate-fade-in-up"
              style={{ animationDelay: `${i * 0.1}s` }}
            >
              <span className="text-accent">$</span>
              <span className={i <= currentStep - 1 ? "text-muted-foreground" : "text-foreground"}>
                {step}
              </span>
              {i <= currentStep - 1 && (
                <span className="text-accent ml-auto">✓</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ScanProgress;
