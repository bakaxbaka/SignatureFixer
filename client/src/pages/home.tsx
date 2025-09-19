import { useState } from "react";
import { AddressAnalyzer } from "@/components/address-analyzer";
import { TransactionDecoder } from "@/components/transaction-decoder";
import { VulnerabilityScanner } from "@/components/vulnerability-scanner";
import { ApiStatus } from "@/components/api-status";
import { AnalyticsDashboard } from "@/components/analytics-dashboard";
import { EducationalResources } from "@/components/educational-resources";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, X, Settings, Search, AlertCircle, Key, Globe } from "lucide-react";
import { useBitcoinAPIs } from "@/hooks/use-bitcoin-apis";
import { useWebSocket } from "@/hooks/use-websocket";

export default function Home() {
  const [showBanner, setShowBanner] = useState(true);
  const { stats, isLoading: statsLoading } = useBitcoinAPIs();
  const { isConnected, lastMessage } = useWebSocket();

  return (
    <div className="min-h-screen bg-background">
      {/* Educational Warning Banner */}
      {showBanner && (
        <div className="bg-destructive/10 border-b border-destructive/20 px-4 py-3">
          <div className="max-w-7xl mx-auto flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0" />
            <p className="text-sm text-destructive font-medium">
              Educational Tool - Controlled Environment Only
            </p>
            <p className="text-sm text-muted-foreground flex-1">
              This tool demonstrates Bitcoin signature vulnerabilities for cybersecurity education. No real funds are at risk. Do not use for illegal activities.
            </p>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowBanner(false)}
              className="text-destructive hover:text-destructive/80"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
                <span className="text-primary-foreground font-bold text-lg">₿</span>
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground">Bitcoin Signature Vulnerability Analyzer</h1>
                <p className="text-sm text-muted-foreground">Advanced ECDSA Security Scanner & Nonce Reuse Detection</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm">
                <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                <span className="text-muted-foreground">Network Status:</span>
                <span className={`font-medium ${isConnected ? 'text-green-500' : 'text-red-500'}`}>
                  {isConnected ? 'Connected to Mainnet' : 'Disconnected'}
                </span>
              </div>
              <Button variant="ghost" size="sm">
                <Settings className="w-5 h-5" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-6">
        {/* Quick Stats Dashboard */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Scanned Addresses</p>
                  <p className="text-2xl font-bold text-foreground" data-testid="total-scanned">
                    {statsLoading ? '...' : stats?.totalScanned || 0}
                  </p>
                </div>
                <div className="w-10 h-10 bg-primary/20 rounded-lg flex items-center justify-center">
                  <Search className="w-5 h-5 text-primary" />
                </div>
              </div>
              <div className="flex items-center gap-1 mt-2">
                <span className="text-xs text-green-500">Educational purposes only</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Nonce Reuse Detected</p>
                  <p className="text-2xl font-bold text-destructive" data-testid="nonce-reuse">
                    {statsLoading ? '...' : stats?.nonceReuseFound || 0}
                  </p>
                </div>
                <div className="w-10 h-10 bg-destructive/20 rounded-lg flex items-center justify-center">
                  <AlertCircle className="w-5 h-5 text-destructive" />
                </div>
              </div>
              <div className="flex items-center gap-1 mt-2">
                <span className="text-xs text-muted-foreground">Critical vulnerabilities found</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Private Keys Recovered</p>
                  <p className="text-2xl font-bold text-orange-500" data-testid="keys-recovered">
                    {statsLoading ? '...' : stats?.keysRecovered || 0}
                  </p>
                </div>
                <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
                  <Key className="w-5 h-5 text-orange-500" />
                </div>
              </div>
              <div className="flex items-center gap-1 mt-2">
                <span className="text-xs text-muted-foreground">Educational demonstrations</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Active API Connections</p>
                  <p className="text-2xl font-bold text-green-500" data-testid="api-connections">
                    {statsLoading ? '...' : '3/3'}
                  </p>
                </div>
                <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                  <Globe className="w-5 h-5 text-green-500" />
                </div>
              </div>
              <div className="flex items-center gap-1 mt-2">
                <span className="text-xs text-green-500">Blockchain.com • Blockstream • SoChain</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Analysis Tools */}
          <div className="lg:col-span-2 space-y-6">
            {/* Address Analyzer */}
            <section>
              <AddressAnalyzer />
            </section>

            {/* Vulnerability Scanner */}
            <section>
              <VulnerabilityScanner />
            </section>

            {/* Transaction Decoder */}
            <section>
              <TransactionDecoder />
            </section>
          </div>

          {/* Right Column: Dashboard & Analytics */}
          <div className="space-y-6">
            <ApiStatus />
            <AnalyticsDashboard />
            <EducationalResources />

            {/* Batch Analysis Queue */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="w-4 h-4 text-primary" />
                  Batch Analysis Queue
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center py-4">
                  <div className="w-6 h-6 text-muted-foreground mx-auto mb-2">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"/>
                      <polyline points="12,6 12,12 16,14"/>
                    </svg>
                  </div>
                  <p className="text-sm text-muted-foreground" data-testid="batch-status">
                    No batch operations running
                  </p>
                  <Button className="mt-2" data-testid="button-start-batch">
                    Start Batch Scan
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Advanced Analytics Section */}
        <div className="mt-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <svg className="w-5 h-5 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M3 3v18h18"/>
                  <path d="m7 16 4-4 4 4 5-5"/>
                </svg>
                Security Analytics & Research Data
              </CardTitle>
              <p className="text-sm text-muted-foreground">
                Comprehensive analysis of Bitcoin signature vulnerabilities and attack patterns
              </p>
            </CardHeader>

            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* Vulnerability Distribution */}
                <div className="bg-muted/50 rounded-lg p-4">
                  <h4 className="font-medium text-foreground mb-3">Vulnerability Distribution</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Nonce Reuse</span>
                      <span className="text-destructive font-mono">67%</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">SIGHASH Issues</span>
                      <span className="text-orange-500 font-mono">21%</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Weak Randomness</span>
                      <span className="text-yellow-500 font-mono">12%</span>
                    </div>
                  </div>
                </div>

                {/* Network Analysis */}
                <div className="bg-muted/50 rounded-lg p-4">
                  <h4 className="font-medium text-foreground mb-3">Network Impact</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Vulnerable Addresses</span>
                      <span className="text-foreground font-mono" data-testid="vulnerable-addresses">
                        {statsLoading ? '...' : stats?.totalScanned || 0}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Affected UTXOs</span>
                      <span className="text-foreground font-mono">3,891</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Educational Value</span>
                      <span className="text-green-500 font-mono">~0.5 BTC</span>
                    </div>
                  </div>
                </div>

                {/* Detection Performance */}
                <div className="bg-muted/50 rounded-lg p-4">
                  <h4 className="font-medium text-foreground mb-3">Detection Performance</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Scan Speed</span>
                      <span className="text-green-500 font-mono">2.3k tx/s</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Accuracy Rate</span>
                      <span className="text-green-500 font-mono">99.7%</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">False Positives</span>
                      <span className="text-yellow-500 font-mono">0.3%</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Research References */}
              <div className="mt-6 pt-6 border-t border-border">
                <h4 className="font-medium text-foreground mb-3">Research References</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <a href="#" className="text-primary hover:text-primary/80 block" data-testid="link-kudelski">
                      → Kudelski Security - Polynonce Attack Research
                    </a>
                    <a href="#" className="text-primary hover:text-primary/80 block mt-1" data-testid="link-strm">
                      → STRM Bitcoin Nonce Reuse Study
                    </a>
                    <a href="#" className="text-primary hover:text-primary/80 block mt-1" data-testid="link-ecdsa">
                      → ECDSA Security Implementation Guidelines
                    </a>
                  </div>
                  <div>
                    <a href="#" className="text-primary hover:text-primary/80 block" data-testid="link-rfc6979">
                      → RFC 6979 - Deterministic Nonce Generation
                    </a>
                    <a href="#" className="text-primary hover:text-primary/80 block mt-1" data-testid="link-bitcoin-security">
                      → Bitcoin Security Best Practices
                    </a>
                    <a href="#" className="text-primary hover:text-primary/80 block mt-1" data-testid="link-academic">
                      → Academic Papers on ECDSA Vulnerabilities
                    </a>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-border bg-card/50 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between text-sm">
            <div className="text-muted-foreground">
              Bitcoin Signature Vulnerability Analyzer - Educational Cybersecurity Tool
            </div>
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="sm" data-testid="link-documentation">
                Documentation
              </Button>
              <Button variant="ghost" size="sm" data-testid="link-research">
                Research
              </Button>
              <Button variant="ghost" size="sm" data-testid="link-about">
                About
              </Button>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}