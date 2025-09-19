import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TrendingUp } from "lucide-react";

interface HistoricalData {
  totalScanned: number;
  nonceReuseFound: number;
  keysRecovered: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
}

export function AnalyticsDashboard() {
  const { data: stats, isLoading } = useQuery<{ data: { statistics: HistoricalData } }>({
    queryKey: ['/api/status'],
    refetchInterval: 60000, // Refresh every minute
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-primary" />
          Historical Nonce Reuse Incidents
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center justify-between">
                <div className="h-4 w-20 bg-muted rounded animate-pulse" />
                <div className="h-4 w-16 bg-muted rounded animate-pulse" />
              </div>
            ))}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">This Month</span>
              <span className="font-mono text-destructive" data-testid="monthly-incidents">
                +{stats?.data?.statistics?.nonceReuseFound || 0} instances
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Total Recovered</span>
              <span className="font-mono text-orange-500" data-testid="total-recovered">
                {stats?.data?.statistics?.keysRecovered || 0} keys
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Critical Issues</span>
              <span className="font-mono text-destructive" data-testid="critical-issues">
                {stats?.data?.statistics?.criticalVulns || 0}
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Avg. Detection Time</span>
              <span className="font-mono text-foreground">0.3s</span>
            </div>
            
            {/* Educational Note */}
            <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded">
              <p className="text-xs text-blue-500">
                ℹ️ All recovered keys and amounts are for educational demonstration only. 
                No real funds are accessed or compromised.
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
