import { useQuery } from "@tanstack/react-query";

interface BitcoinStats {
  totalScanned: number;
  nonceReuseFound: number;
  keysRecovered: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
}

export function useBitcoinAPIs() {
  const { data: status, isLoading, error } = useQuery<{
    success: boolean;
    data: {
      apiConnections: Array<{
        provider: string;
        status: string;
        responseTime: number;
      }>;
      statistics: BitcoinStats;
      timestamp: string;
    };
  }>({
    queryKey: ['/api/status'],
    refetchInterval: 30000, // Refresh every 30 seconds
    retry: 3,
    retryDelay: attemptIndex => Math.min(1000 * 2 ** attemptIndex, 30000),
  });

  return {
    stats: status?.data?.statistics,
    apiConnections: status?.data?.apiConnections || [],
    isLoading,
    error,
    isConnected: status?.data?.apiConnections?.some(api => api.status === 'online') || false,
    lastUpdate: status?.data?.timestamp ? new Date(status.data.timestamp) : null,
  };
}
