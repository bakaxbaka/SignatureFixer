import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity } from "lucide-react";

interface ApiConnection {
  provider: string;
  status: string;
  responseTime: number;
}

interface SystemStatus {
  apiConnections: ApiConnection[];
  statistics: {
    totalScanned: number;
    nonceReuseFound: number;
    keysRecovered: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
  };
  timestamp: string;
}

export function ApiStatus() {
  const { data: status, isLoading } = useQuery<{ data: SystemStatus }>({
    queryKey: ['/api/status'],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-500';
      case 'error': return 'text-red-500';
      default: return 'text-yellow-500';
    }
  };

  const getStatusDot = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-500';
      case 'error': return 'bg-red-500';
      default: return 'bg-yellow-500';
    }
  };

  const getProviderName = (provider: string) => {
    switch (provider) {
      case 'blockchain_com': return 'Blockchain.com';
      case 'blockstream': return 'Blockstream Esplora';
      case 'sochain': return 'SoChain API';
      default: return provider;
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-primary" />
          API Connection Status
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-muted rounded-full animate-pulse" />
                  <div className="h-4 w-20 bg-muted rounded animate-pulse" />
                </div>
                <div className="h-3 w-12 bg-muted rounded animate-pulse" />
              </div>
            ))}
          </div>
        ) : status?.data?.apiConnections ? (
          status.data.apiConnections.map((api, index) => (
            <div key={index} className="flex items-center justify-between" data-testid={`api-status-${api.provider}`}>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${getStatusDot(api.status)}`} />
                <span className="text-sm font-medium">
                  {getProviderName(api.provider)}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className={`text-xs ${getStatusColor(api.status)}`}>
                  {api.status}
                </div>
                {api.responseTime > 0 && (
                  <div className="text-xs text-muted-foreground">
                    {api.responseTime}ms
                  </div>
                )}
              </div>
            </div>
          ))
        ) : (
          <div className="text-center py-4">
            <p className="text-muted-foreground text-sm">Unable to fetch API status</p>
          </div>
        )}
        
        {status?.data?.timestamp && (
          <div className="pt-2 border-t border-border">
            <p className="text-xs text-muted-foreground">
              Last updated: {new Date(status.data.timestamp).toLocaleTimeString()}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
