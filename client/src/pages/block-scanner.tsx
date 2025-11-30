import { useState, useEffect, useCallback } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Link } from "wouter";
import {
  AlertTriangle,
  Search,
  Play,
  Pause,
  BarChart3,
  Blocks,
  Radio,
  ArrowLeft,
  RefreshCw,
  Activity,
  Shield,
  Zap,
  Clock,
  Database,
} from "lucide-react";

const blockScanSchema = z.object({
  startBlock: z.string().min(1, "Start block is required").regex(/^\d+$/, "Must be a number"),
  endBlock: z.string().min(1, "End block is required").regex(/^\d+$/, "Must be a number"),
});

type BlockScanForm = z.infer<typeof blockScanSchema>;

interface ScanProgress {
  currentBlock: number;
  totalBlocks: number;
  vulnerabilitiesFound: number;
  startTime: number;
}

interface ScanResult {
  blockHeight?: number;
  txid: string;
  address: string;
  vulnerabilityType?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: number;
}

interface RValueStats {
  totalUniqueR: number;
  reusedR: number;
  rValueDistribution: Array<{ r: string; count: number }>;
}

export default function BlockScanner() {
  const [activeTab, setActiveTab] = useState("block-scan");
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [mempoolResults, setMempoolResults] = useState<any[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const { toast } = useToast();

  const blockScanForm = useForm<BlockScanForm>({
    resolver: zodResolver(blockScanSchema),
    defaultValues: { startBlock: "", endBlock: "" },
  });

  const { data: blockHeight, refetch: refetchHeight } = useQuery<{ success: boolean; data: { height: number } }>({
    queryKey: ['/api/blockchain/height'],
  });

  const { data: scannerStats, refetch: refetchStats } = useQuery<{ success: boolean; data: RValueStats }>({
    queryKey: ['/api/scanner/statistics'],
  });

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => {
      setWsConnected(true);
      console.log('WebSocket connected for scanner updates');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'scan_progress') {
          setScanProgress(data);
        } else if (data.type === 'vulnerability_found') {
          setScanResults(prev => [data, ...prev].slice(0, 50));
          toast({
            title: "Vulnerability Found!",
            description: `${data.vulnerabilityType} in block ${data.blockHeight}`,
            variant: "destructive",
          });
        } else if (data.type === 'mempool_vulnerability') {
          toast({
            title: "Mempool Alert",
            description: `Potential ${data.vulnerability} in ${data.txid.slice(0, 16)}...`,
            variant: "destructive",
          });
        }
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    };

    ws.onclose = () => {
      setWsConnected(false);
      console.log('WebSocket disconnected');
    };

    return () => {
      ws.close();
    };
  }, [toast]);

  const blockScanMutation = useMutation({
    mutationFn: async (data: { startBlock: number; endBlock: number }) => {
      const response = await apiRequest("POST", "/api/scanner/scan-blocks", data);
      return response.json();
    },
    onSuccess: (result) => {
      if (result.data?.results) {
        setScanResults(result.data.results);
      }
      refetchStats();
      toast({
        title: "Scan Complete",
        description: `Scanned ${result.data?.scannedBlocks} blocks, found ${result.data?.vulnerabilitiesFound} vulnerabilities`,
      });
    },
    onError: (error) => {
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const mempoolScanMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/scanner/scan-mempool", {});
      return response.json();
    },
    onSuccess: (result) => {
      if (result.data?.results) {
        setMempoolResults(result.data.results);
      }
      refetchStats();
      toast({
        title: "Mempool Scan Complete",
        description: `Scanned ${result.data?.transactionsScanned} transactions, found ${result.data?.vulnerabilities} vulnerabilities`,
      });
    },
    onError: (error) => {
      toast({
        title: "Mempool Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const stopScanMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/scanner/stop", {});
      return response.json();
    },
    onSuccess: () => {
      setScanProgress(null);
      toast({
        title: "Scan Stopped",
        description: "Block scanning has been stopped",
      });
    },
  });

  const onBlockScanSubmit = (data: BlockScanForm) => {
    const startBlock = parseInt(data.startBlock, 10);
    const endBlock = parseInt(data.endBlock, 10);

    if (endBlock - startBlock > 100) {
      toast({
        title: "Range Too Large",
        description: "Maximum scan range is 100 blocks",
        variant: "destructive",
      });
      return;
    }

    if (endBlock < startBlock) {
      toast({
        title: "Invalid Range",
        description: "End block must be greater than start block",
        variant: "destructive",
      });
      return;
    }

    setScanResults([]);
    blockScanMutation.mutate({ startBlock, endBlock });
  };

  const setLatestBlocks = () => {
    if (blockHeight?.data?.height) {
      const height = blockHeight.data.height;
      blockScanForm.setValue("startBlock", String(height - 9));
      blockScanForm.setValue("endBlock", String(height));
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const progressPercent = scanProgress 
    ? Math.round(((scanProgress.currentBlock - scanProgress.totalBlocks + scanProgress.totalBlocks) / scanProgress.totalBlocks) * 100)
    : 0;

  return (
    <div className="min-h-screen bg-background">
      <div className="bg-destructive/10 border-b border-destructive/20 px-4 py-3">
        <div className="max-w-7xl mx-auto flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0" />
          <p className="text-sm text-destructive font-medium">
            Educational Tool - Research Purposes Only
          </p>
          <p className="text-sm text-muted-foreground flex-1">
            This scanner demonstrates blockchain vulnerability detection for cybersecurity education.
          </p>
        </div>
      </div>

      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Link href="/">
                <Button variant="ghost" size="sm" data-testid="button-back-home">
                  <ArrowLeft className="w-4 h-4 mr-2" />
                  Back
                </Button>
              </Link>
              <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
                <Search className="w-5 h-5 text-primary-foreground" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground">Block Scanner</h1>
                <p className="text-sm text-muted-foreground">
                  Real-time Blockchain Vulnerability Detection
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant={wsConnected ? "default" : "destructive"} className="gap-1">
                <Radio className="w-3 h-3" />
                {wsConnected ? "Live" : "Disconnected"}
              </Badge>
              {blockHeight?.data?.height && (
                <Badge variant="outline" className="gap-1">
                  <Blocks className="w-3 h-3" />
                  Block #{blockHeight.data.height.toLocaleString()}
                </Badge>
              )}
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6">
          <Card className="bg-primary/10 border-primary/20">
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-primary/20 rounded-lg flex items-center justify-center">
                  <BarChart3 className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Unique R Values</p>
                  <p className="text-2xl font-bold" data-testid="text-unique-r-count">
                    {scannerStats?.data?.totalUniqueR?.toLocaleString() || 0}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-destructive/10 border-destructive/20">
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-destructive/20 rounded-lg flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 text-destructive" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Reused Nonces</p>
                  <p className="text-2xl font-bold text-destructive" data-testid="text-reused-nonce-count">
                    {scannerStats?.data?.reusedR?.toLocaleString() || 0}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-muted rounded-lg flex items-center justify-center">
                  <Activity className="w-5 h-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Scan Results</p>
                  <p className="text-2xl font-bold" data-testid="text-scan-results-count">
                    {scanResults.length}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-muted rounded-lg flex items-center justify-center">
                  <Database className="w-5 h-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Mempool TXs</p>
                  <p className="text-2xl font-bold" data-testid="text-mempool-count">
                    {mempoolResults.length}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {scanProgress && (
          <Card className="mb-6 border-primary/20">
            <CardContent className="pt-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-primary" />
                  <span className="text-sm font-medium">Scanning Block {scanProgress.currentBlock.toLocaleString()}</span>
                </div>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => stopScanMutation.mutate()}
                  data-testid="button-stop-scan"
                >
                  <Pause className="w-4 h-4 mr-2" />
                  Stop
                </Button>
              </div>
              <Progress value={progressPercent} className="h-2" />
              <div className="flex justify-between mt-2 text-xs text-muted-foreground">
                <span>Vulnerabilities Found: {scanProgress.vulnerabilitiesFound}</span>
                <span>{progressPercent}% Complete</span>
              </div>
            </CardContent>
          </Card>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid grid-cols-3 w-full max-w-md">
            <TabsTrigger value="block-scan" data-testid="tab-block-scan">
              <Blocks className="w-4 h-4 mr-2" />
              Block Scan
            </TabsTrigger>
            <TabsTrigger value="mempool" data-testid="tab-mempool">
              <Radio className="w-4 h-4 mr-2" />
              Mempool
            </TabsTrigger>
            <TabsTrigger value="results" data-testid="tab-results">
              <Shield className="w-4 h-4 mr-2" />
              Results
            </TabsTrigger>
          </TabsList>

          <TabsContent value="block-scan" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Blocks className="w-5 h-5 text-primary" />
                  Block Range Scanner
                </CardTitle>
                <CardDescription>
                  Scan a range of Bitcoin blocks for ECDSA signature vulnerabilities including nonce reuse and weak nonces
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={blockScanForm.handleSubmit(onBlockScanSubmit)} className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="startBlock">Start Block</Label>
                      <Input
                        id="startBlock"
                        placeholder="e.g., 810000"
                        {...blockScanForm.register("startBlock")}
                        data-testid="input-start-block"
                      />
                      {blockScanForm.formState.errors.startBlock && (
                        <p className="text-sm text-destructive">
                          {blockScanForm.formState.errors.startBlock.message}
                        </p>
                      )}
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="endBlock">End Block</Label>
                      <Input
                        id="endBlock"
                        placeholder="e.g., 810010"
                        {...blockScanForm.register("endBlock")}
                        data-testid="input-end-block"
                      />
                      {blockScanForm.formState.errors.endBlock && (
                        <p className="text-sm text-destructive">
                          {blockScanForm.formState.errors.endBlock.message}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={setLatestBlocks}
                      disabled={!blockHeight?.data?.height}
                      data-testid="button-set-latest-blocks"
                    >
                      <Clock className="w-4 h-4 mr-2" />
                      Use Latest 10 Blocks
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => refetchHeight()}
                      data-testid="button-refresh-height"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </Button>
                  </div>
                  <Separator />
                  <Button
                    type="submit"
                    className="w-full"
                    disabled={blockScanMutation.isPending || !!scanProgress}
                    data-testid="button-start-block-scan"
                  >
                    {blockScanMutation.isPending ? (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                        Scanning Blocks...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 mr-2" />
                        Start Block Scan
                      </>
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Alert>
              <Zap className="h-4 w-4" />
              <AlertTitle>How It Works</AlertTitle>
              <AlertDescription>
                The scanner analyzes DER-encoded signatures in Bitcoin transactions, 
                extracting R and S values to detect nonce reuse and other ECDSA vulnerabilities.
                Maximum scan range is 100 blocks to prevent API rate limiting.
              </AlertDescription>
            </Alert>
          </TabsContent>

          <TabsContent value="mempool" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Radio className="w-5 h-5 text-primary" />
                  Mempool Scanner
                </CardTitle>
                <CardDescription>
                  Scan unconfirmed transactions in the mempool for potential signature vulnerabilities
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Button
                  className="w-full"
                  onClick={() => mempoolScanMutation.mutate()}
                  disabled={mempoolScanMutation.isPending}
                  data-testid="button-scan-mempool"
                >
                  {mempoolScanMutation.isPending ? (
                    <>
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      Scanning Mempool...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      Scan Mempool Transactions
                    </>
                  )}
                </Button>

                {mempoolResults.length > 0 && (
                  <div className="space-y-2">
                    <Separator />
                    <h4 className="font-medium text-sm">Recent Mempool Results</h4>
                    <div className="max-h-64 overflow-y-auto space-y-2">
                      {mempoolResults.slice(0, 20).map((result, index) => (
                        <div
                          key={index}
                          className={`p-3 rounded-lg border ${
                            result.potentialVulnerability 
                              ? 'border-destructive/50 bg-destructive/5' 
                              : 'border-border'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <code className="text-xs font-mono">
                              {result.txid.slice(0, 32)}...
                            </code>
                            {result.potentialVulnerability && (
                              <Badge variant="destructive" className="text-xs">
                                {result.potentialVulnerability}
                              </Badge>
                            )}
                          </div>
                          <div className="flex gap-4 mt-1 text-xs text-muted-foreground">
                            <span>Size: {result.size} bytes</span>
                            <span>Signatures: {result.signatures?.length || 0}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="results" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-primary" />
                  Detected Vulnerabilities
                </CardTitle>
                <CardDescription>
                  Vulnerabilities discovered during scanning operations
                </CardDescription>
              </CardHeader>
              <CardContent>
                {scanResults.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No vulnerabilities detected yet</p>
                    <p className="text-sm">Start a scan to find ECDSA signature vulnerabilities</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {scanResults.map((result, index) => (
                      <div
                        key={index}
                        className="p-4 rounded-lg border border-border bg-card"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${getSeverityColor(result.severity)}`} />
                            <span className="font-medium text-sm">
                              {result.vulnerabilityType?.replace(/_/g, ' ').toUpperCase()}
                            </span>
                          </div>
                          <Badge variant="outline">{result.severity}</Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                          <div>
                            <span className="block text-foreground font-medium">Block</span>
                            {result.blockHeight?.toLocaleString() || 'N/A'}
                          </div>
                          <div>
                            <span className="block text-foreground font-medium">Transaction</span>
                            <code className="font-mono">{result.txid?.slice(0, 16)}...</code>
                          </div>
                          <div className="col-span-2">
                            <span className="block text-foreground font-medium">Address</span>
                            <code className="font-mono">{result.address}</code>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {scannerStats?.data?.rValueDistribution && scannerStats.data.rValueDistribution.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-primary" />
                    R-Value Distribution (Top Reused)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {scannerStats.data.rValueDistribution.map((item, index) => (
                      <div key={index} className="flex items-center gap-3">
                        <code className="text-xs font-mono bg-muted rounded px-2 py-1 flex-1">
                          {item.r}
                        </code>
                        <Badge variant="destructive">{item.count} uses</Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
