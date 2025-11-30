import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Copy, AlertTriangle, CheckCircle, XCircle, Zap } from "lucide-react";
import { Cve42461Report } from "@/engines/cve42461";
import { detectInputType, getTypeLabel, validateDetectedType } from "@/lib/input-detector";
import { TransactionInspector } from "@/components/transaction-inspector";

export default function SignatureTools() {
  const { toast } = useToast();
  const [txidInput, setTxidInput] = useState("");
  const [txHexResult, setTxHexResult] = useState("");
  const [hexLoading, setHexLoading] = useState(false);
  const [txHexInput, setTxHexInput] = useState("");
  const [sigResult, setSigResult] = useState<any>(null);
  const [sigLoading, setSigLoading] = useState(false);
  const [builderData, setBuilderData] = useState({
    wif: "",
    prevTxId: "",
    prevVout: "0",
    prevValue: "",
    prevScriptHex: "",
    destValue: "",
    destScriptHex: "",
  });
  const [builtTx, setBuiltTx] = useState<any>(null);
  const [buildLoading, setBuildLoading] = useState(false);
  const [cveLibraryName, setCveLibraryName] = useState("elliptic");
  const [cveLoading, setCveLoading] = useState(false);
  const [cveReport, setCveReport] = useState<Cve42461Report | null>(null);
  const [smartInput, setSmartInput] = useState("");
  const detectedInput = detectInputType(smartInput);
  const [parsedTxid, setParsedTxid] = useState<string | null>(null);
  const [parsedTxHex, setParsedTxHex] = useState<string | null>(null);

  const fetchTxHex = async () => {
    if (!txidInput.trim()) {
      toast({ title: "Error", description: "Enter a transaction ID", variant: "destructive" });
      return;
    }
    setHexLoading(true);
    try {
      const res = await fetch("/api/get-tx-hex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ txid: txidInput }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed");
      setTxHexResult(data.data.hex);
      toast({ title: "Success", description: "TX hex fetched" });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setHexLoading(false);
    }
  };

  const extractSignatures = async () => {
    if (!txHexInput.trim()) {
      toast({ title: "Error", description: "Paste TX hex", variant: "destructive" });
      return;
    }
    setSigLoading(true);
    try {
      const res = await fetch("/api/extract-signatures", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ txHex: txHexInput }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed");
      setSigResult(data.data);
      toast({ title: "Success", description: `Found ${data.data.count} signatures` });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setSigLoading(false);
    }
  };

  const buildAndSign = async () => {
    if (!builderData.wif || !builderData.prevTxId || !builderData.prevValue || !builderData.destValue) {
      toast({ title: "Error", description: "Fill all required fields", variant: "destructive" });
      return;
    }
    setBuildLoading(true);
    try {
      const res = await fetch("/api/build-and-sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(builderData),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed");
      setBuiltTx(data.data);
      toast({ title: "Success", description: "Transaction signed with DER mutations" });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setBuildLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied" });
  };

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8">
          <h1 className="text-4xl font-bold">Signature Tools</h1>
          <p className="text-muted-foreground mt-2">SegWit + Legacy support • DER malleability variants • Full signature extraction</p>
        </div>

        <Tabs defaultValue="fetch-hex" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="fetch-hex">Fetch TX Hex</TabsTrigger>
            <TabsTrigger value="extract-sig">Extract Signatures</TabsTrigger>
            <TabsTrigger value="build-sign">Build & Sign</TabsTrigger>
            <TabsTrigger value="cve-42461">CVE-2024-42461</TabsTrigger>
          </TabsList>

          <TabsContent value="fetch-hex" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="w-5 h-5 text-blue-500" />
                  Smart Transaction Inspector
                </CardTitle>
                <CardDescription>Paste TX ID, raw hex, PSBT, signature, or script - auto-detects type</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <Textarea
                    placeholder="Paste: Transaction ID (64 hex) • Raw TX hex • PSBT (base64) • DER Signature • Script hex"
                    value={smartInput}
                    onChange={(e) => setSmartInput(e.target.value)}
                    rows={4}
                    className="font-mono text-xs"
                    data-testid="input-smart-inspector"
                  />
                  {smartInput && (
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={detectedInput.confidence > 0.7 ? "default" : "outline"}
                        className={
                          detectedInput.confidence > 0.7
                            ? "bg-blue-600 text-white"
                            : "bg-gray-200 text-gray-700"
                        }
                      >
                        Detected: {getTypeLabel(detectedInput.type)}
                      </Badge>
                      {detectedInput.details && (
                        <span className="text-xs text-muted-foreground">{detectedInput.details}</span>
                      )}
                    </div>
                  )}
                </div>

                {detectedInput.type === "txid" && (
                  <Button
                    onClick={async () => {
                      setTxidInput(smartInput);
                      setHexLoading(true);
                      try {
                        const res = await fetch("/api/get-tx-hex", {
                          method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify({ txid: smartInput }),
                        });
                        const data = await res.json();
                        if (!res.ok) throw new Error(data.error || "Failed");
                        const hex = data.data.hex;
                        setTxHexResult(hex);
                        setParsedTxid(smartInput);
                        setParsedTxHex(hex);
                        setSmartInput("");
                        toast({ title: "Success", description: "TX hex fetched & analyzing..." });
                      } catch (e) {
                        toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
                      } finally {
                        setHexLoading(false);
                      }
                    }}
                    disabled={hexLoading}
                    className="w-full bg-blue-600 hover:bg-blue-700"
                  >
                    {hexLoading ? "Fetching..." : "Fetch & Decode TX"}
                  </Button>
                )}

                {detectedInput.type === "raw-tx" && (
                  <Button
                    onClick={() => {
                      setTxHexInput(smartInput);
                      setParsedTxHex(smartInput);
                      setSmartInput("");
                      toast({ title: "Success", description: "Raw TX loaded & analyzing..." });
                    }}
                    className="w-full bg-green-600 hover:bg-green-700"
                  >
                    Analyze Raw TX →
                  </Button>
                )}

                {detectedInput.type === "der-signature" && (
                  <Button
                    onClick={() => {
                      navigator.clipboard.writeText(smartInput);
                      setSmartInput("");
                      toast({ title: "Copied", description: "Signature copied to clipboard" });
                    }}
                    variant="outline"
                    className="w-full"
                  >
                    Copy Signature to Clipboard
                  </Button>
                )}

                <div className="border-t pt-4">
                  <h4 className="font-semibold text-sm mb-3">Or use classic input:</h4>
                </div>

                <Input placeholder="Transaction ID" value={txidInput} onChange={(e) => setTxidInput(e.target.value)} data-testid="input-txid" />
                <Button onClick={fetchTxHex} disabled={hexLoading} className="w-full">
                  {hexLoading ? "Fetching..." : "Fetch Hex"}
                </Button>
                {parsedTxHex && (
                  <div className="space-y-6 border-t pt-6">
                    <h4 className="font-semibold text-lg">Transaction Analysis</h4>
                    <TransactionInspector txHex={parsedTxHex} txid={parsedTxid || undefined} />
                  </div>
                )}

                {txHexResult && !parsedTxHex && (
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <label className="text-sm font-medium">TX Hex:</label>
                      <Button size="sm" variant="outline" onClick={() => copyToClipboard(txHexResult)}>
                        <Copy className="w-4 h-4 mr-2" /> Copy
                      </Button>
                    </div>
                    <Textarea value={txHexResult} readOnly rows={6} className="font-mono text-xs" />
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="extract-sig" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Extract Signatures</CardTitle>
                <CardDescription>Supports SegWit (P2WPKH witness) & Legacy (scriptSig)</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Textarea placeholder="Paste TX hex..." value={txHexInput} onChange={(e) => setTxHexInput(e.target.value)} rows={6} className="font-mono text-xs" />
                <Button onClick={extractSignatures} disabled={sigLoading} className="w-full">
                  {sigLoading ? "Extracting..." : "Extract Signatures"}
                </Button>

                {sigResult && (
                  <div className="space-y-4">
                    <div className="bg-muted p-4 rounded">
                      <p className="text-sm font-medium">Found {sigResult.count} signature(s)</p>
                    </div>
                    {sigResult.signatures.map((sig: any, idx: number) => (
                      <div key={idx} className="border rounded p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium">Input #{sig.index}</p>
                          <Badge>{sig.type}</Badge>
                        </div>
                        <div>
                          <label className="text-xs text-muted-foreground">Signature (DER):</label>
                          <div className="font-mono text-xs break-all bg-muted p-2 rounded mt-1">{sig.signature}</div>
                        </div>
                        {sig.pubkey && (
                          <div>
                            <label className="text-xs text-muted-foreground">Public Key:</label>
                            <div className="font-mono text-xs break-all bg-muted p-2 rounded mt-1">{sig.pubkey}</div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="build-sign" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Build & Sign Transaction</CardTitle>
                <CardDescription>Generate signed TX with DER malleability variants</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <Input placeholder="Private Key (WIF)" type="password" value={builderData.wif} onChange={(e) => setBuilderData({ ...builderData, wif: e.target.value })} />
                  <Input placeholder="Previous TX ID" value={builderData.prevTxId} onChange={(e) => setBuilderData({ ...builderData, prevTxId: e.target.value })} />
                  <Input placeholder="Prev Output Index" type="number" value={builderData.prevVout} onChange={(e) => setBuilderData({ ...builderData, prevVout: e.target.value })} />
                  <Input placeholder="Prev Value (sats)" type="number" value={builderData.prevValue} onChange={(e) => setBuilderData({ ...builderData, prevValue: e.target.value })} />
                  <Input placeholder="Prev Script (hex)" value={builderData.prevScriptHex} onChange={(e) => setBuilderData({ ...builderData, prevScriptHex: e.target.value })} />
                  <Input placeholder="Dest Value (sats)" type="number" value={builderData.destValue} onChange={(e) => setBuilderData({ ...builderData, destValue: e.target.value })} />
                </div>
                <Input placeholder="Dest Script (hex)" value={builderData.destScriptHex} onChange={(e) => setBuilderData({ ...builderData, destScriptHex: e.target.value })} />
                <Button onClick={buildAndSign} disabled={buildLoading} className="w-full">
                  {buildLoading ? "Building..." : "Build & Sign"}
                </Button>

                {builtTx && (
                  <div className="space-y-6">
                    <div className="space-y-2 border-t pt-6">
                      <h4 className="font-semibold text-sm">Signed Transaction</h4>
                      <div>
                        <label className="text-xs text-muted-foreground">TXID:</label>
                        <Button size="sm" variant="outline" onClick={() => copyToClipboard(builtTx.txId)} className="ml-2 mb-2">
                          <Copy className="w-4 h-4 mr-2" /> Copy
                        </Button>
                        <code className="block bg-muted p-2 rounded font-mono text-xs break-all">{builtTx.txId}</code>
                      </div>
                      <div className="mt-2">
                        <label className="text-xs text-muted-foreground">TX Hex:</label>
                        <Button size="sm" variant="outline" onClick={() => copyToClipboard(builtTx.txHex)} className="ml-2 mb-2">
                          <Copy className="w-4 h-4 mr-2" /> Copy
                        </Button>
                        <Textarea value={builtTx.txHex} readOnly rows={4} className="font-mono text-xs" />
                      </div>
                    </div>

                    {builtTx.mutations && builtTx.mutations.length > 0 && (
                      <div className="space-y-4 border-t pt-6">
                        <h4 className="font-semibold text-sm">DER Malleability Variants ({builtTx.mutations.length})</h4>
                        {builtTx.mutations.map((mut: any, idx: number) => (
                          <div key={idx} className="border rounded p-3 space-y-2 bg-card/50">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Badge variant={mut.isValid ? "default" : "destructive"}>{mut.mutation}</Badge>
                                <span className="text-xs text-muted-foreground">{mut.description}</span>
                              </div>
                              <Button size="sm" variant="outline" onClick={() => copyToClipboard(mut.mutated)}>
                                <Copy className="w-3 h-3" />
                              </Button>
                            </div>
                            <div>
                              <label className="text-xs text-muted-foreground block">Original:</label>
                              <code className="block bg-muted p-2 rounded font-mono text-xs break-all">{mut.original}</code>
                            </div>
                            <div>
                              <label className="text-xs text-muted-foreground block">Mutated:</label>
                              <code className="block bg-muted p-2 rounded font-mono text-xs break-all">{mut.mutated}</code>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="cve-42461" className="space-y-4">
            <Card className="border-amber-500/20 bg-amber-500/5">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-500" />
                  CVE-2024-42461: Signature Malleability Detection
                </CardTitle>
                <CardDescription>
                  Test if a library/wallet accepts non-canonical DER encodings like vulnerable elliptic 6.5.6
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4">
                  <p className="text-sm text-amber-700 dark:text-amber-300">
                    This tool tests signature verification functions against malleated BER encodings. A vulnerable implementation
                    (like elliptic 6.5.6) will accept non-canonical signatures, allowing attackers to manipulate transactions.
                  </p>
                </div>

                <div className="space-y-3">
                  <label className="text-sm font-medium">Library/Service Name</label>
                  <Input
                    placeholder="e.g., elliptic, bitcoinjs-lib, noble-secp256k1, Ledger, Trezor"
                    value={cveLibraryName}
                    onChange={(e) => setCveLibraryName(e.target.value)}
                    data-testid="input-library-name"
                  />
                </div>

                <Button
                  onClick={async () => {
                    if (!cveLibraryName.trim()) {
                      toast({ title: "Error", description: "Enter library name", variant: "destructive" });
                      return;
                    }
                    setCveLoading(true);
                    try {
                      const res = await fetch("/api/test-cve-42461", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ libraryName: cveLibraryName }),
                      });
                      const data = await res.json();
                      if (!res.ok) throw new Error(data.error || "Test failed");
                      setCveReport(data.data);
                      toast({ title: "Test Complete", description: `Library: ${data.data.summary}` });
                    } catch (e) {
                      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
                    } finally {
                      setCveLoading(false);
                    }
                  }}
                  disabled={cveLoading}
                  className="w-full"
                >
                  {cveLoading ? "Testing..." : "Run CVE-2024-42461 Test"}
                </Button>

                {cveReport && (
                  <div className="space-y-6 border-t pt-6">
                    <div className="space-y-4">
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="font-semibold text-lg">{cveReport.libraryName}</h4>
                          <p className="text-sm text-muted-foreground">{cveReport.summary}</p>
                        </div>
                        <Badge
                          variant={cveReport.vulnerable ? "destructive" : "default"}
                          className={
                            cveReport.vulnerable
                              ? "bg-red-600 text-white"
                              : "bg-green-600 text-white"
                          }
                        >
                          {cveReport.vulnerable ? "VULNERABLE" : "SECURE"}
                        </Badge>
                      </div>

                      <div className="grid grid-cols-3 gap-4">
                        <div className="border rounded p-3">
                          <p className="text-xs text-muted-foreground mb-1">Canonical DER</p>
                          <div className="flex items-center gap-2">
                            {cveReport.acceptsCanonicalDER ? (
                              <CheckCircle className="w-5 h-5 text-green-500" />
                            ) : (
                              <XCircle className="w-5 h-5 text-red-500" />
                            )}
                            <span className="font-mono text-sm">
                              {cveReport.acceptsCanonicalDER ? "PASS" : "FAIL"}
                            </span>
                          </div>
                        </div>
                        <div className="border rounded p-3">
                          <p className="text-xs text-muted-foreground mb-1">BER Variants</p>
                          <div className="flex items-center gap-2">
                            {cveReport.acceptsBERVariants ? (
                              <XCircle className="w-5 h-5 text-red-500" />
                            ) : (
                              <CheckCircle className="w-5 h-5 text-green-500" />
                            )}
                            <span className="font-mono text-sm">
                              {cveReport.acceptsBERVariants ? "FAIL" : "PASS"}
                            </span>
                          </div>
                        </div>
                        <div className="border rounded p-3">
                          <p className="text-xs text-muted-foreground mb-1">Severity</p>
                          <Badge
                            variant="outline"
                            className={`w-full justify-center ${
                              cveReport.severity === "CRITICAL"
                                ? "bg-red-100 text-red-700"
                                : cveReport.severity === "HIGH"
                                  ? "bg-orange-100 text-orange-700"
                                  : cveReport.severity === "MEDIUM"
                                    ? "bg-yellow-100 text-yellow-700"
                                    : "bg-green-100 text-green-700"
                            }`}
                          >
                            {cveReport.severity}
                          </Badge>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-3">
                      <h5 className="font-semibold text-sm">Test Cases</h5>
                      {cveReport.testCases.map((tc) => (
                        <div
                          key={tc.id}
                          className={`border rounded p-3 ${
                            tc.didVerify === tc.shouldVerify ? "bg-green-500/5" : "bg-red-500/5"
                          }`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              {tc.didVerify === tc.shouldVerify ? (
                                <CheckCircle className="w-4 h-4 text-green-500" />
                              ) : (
                                <XCircle className="w-4 h-4 text-red-500" />
                              )}
                              <span className="font-mono text-sm">{tc.encodingType}</span>
                            </div>
                            <span className="text-xs text-muted-foreground">
                              Should: {tc.shouldVerify ? "✓" : "✗"} | Did: {tc.didVerify ? "✓" : "✗"}
                            </span>
                          </div>
                          {tc.description && (
                            <p className="text-xs text-muted-foreground">{tc.description}</p>
                          )}
                          {tc.derHex && (
                            <div className="mt-2 p-2 bg-muted rounded">
                              <p className="text-xs font-mono break-all text-foreground">{tc.derHex}</p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
