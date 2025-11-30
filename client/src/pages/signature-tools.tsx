import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Copy } from "lucide-react";

export default function SignatureTools() {
  const { toast } = useToast();

  // TX Hex Fetcher
  const [txidInput, setTxidInput] = useState("");
  const [txHexResult, setTxHexResult] = useState("");
  const [hexLoading, setHexLoading] = useState(false);

  // Signature Extractor
  const [txHexInput, setTxHexInput] = useState("");
  const [sigResult, setSigResult] = useState<any>(null);
  const [sigLoading, setSigLoading] = useState(false);

  // Transaction Builder
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
      if (!res.ok) throw new Error(data.error || "Failed to fetch");
      setTxHexResult(data.data.hex);
      toast({ title: "Success", description: "Transaction hex fetched" });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setHexLoading(false);
    }
  };

  const extractSignatures = async () => {
    if (!txHexInput.trim()) {
      toast({ title: "Error", description: "Paste transaction hex", variant: "destructive" });
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
      toast({ title: "Success", description: `Extracted ${data.data.count} signatures` });
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
      toast({ title: "Success", description: "Transaction signed with DER mutations generated" });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setBuildLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied", description: "Copied to clipboard" });
  };

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8">
          <h1 className="text-4xl font-bold">Signature Tools</h1>
          <p className="text-muted-foreground mt-2">Fetch transaction hex, extract signatures, and build signed transactions with DER malleability variants</p>
        </div>

        <Tabs defaultValue="fetch-hex" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="fetch-hex">Fetch TX Hex</TabsTrigger>
            <TabsTrigger value="extract-sig">Extract Signatures</TabsTrigger>
            <TabsTrigger value="build-sign">Build & Sign</TabsTrigger>
          </TabsList>

          {/* Fetch TX Hex */}
          <TabsContent value="fetch-hex" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Fetch Transaction Hex</CardTitle>
                <CardDescription>Get raw transaction hex from blockchain APIs</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Input placeholder="Transaction ID" value={txidInput} onChange={(e) => setTxidInput(e.target.value)} data-testid="input-txid" />
                <Button onClick={fetchTxHex} disabled={hexLoading} className="w-full">
                  {hexLoading ? "Fetching..." : "Fetch Hex"}
                </Button>

                {txHexResult && (
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <label className="text-sm font-medium">Transaction Hex:</label>
                      <Button size="sm" variant="outline" onClick={() => copyToClipboard(txHexResult)} data-testid="button-copy-hex">
                        <Copy className="w-4 h-4 mr-2" /> Copy
                      </Button>
                    </div>
                    <Textarea value={txHexResult} readOnly rows={6} className="font-mono text-xs" />
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Extract Signatures */}
          <TabsContent value="extract-sig" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Extract Signatures</CardTitle>
                <CardDescription>Parse signatures and public keys from transaction hex</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Textarea placeholder="Paste transaction hex..." value={txHexInput} onChange={(e) => setTxHexInput(e.target.value)} rows={6} className="font-mono text-xs" data-testid="textarea-tx-hex" />
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
                        <p className="text-sm font-medium">Input #{sig.index}</p>
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

          {/* Build & Sign */}
          <TabsContent value="build-sign" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Build & Sign Transaction</CardTitle>
                <CardDescription>Create and sign transaction with automatic DER malleability variants</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <Input placeholder="Private Key (WIF)" type="password" value={builderData.wif} onChange={(e) => setBuilderData({ ...builderData, wif: e.target.value })} data-testid="input-wif" />
                  <Input placeholder="Previous TX ID" value={builderData.prevTxId} onChange={(e) => setBuilderData({ ...builderData, prevTxId: e.target.value })} data-testid="input-prev-txid" />
                  <Input placeholder="Previous Output Index" type="number" value={builderData.prevVout} onChange={(e) => setBuilderData({ ...builderData, prevVout: e.target.value })} data-testid="input-prev-vout" />
                  <Input placeholder="Previous Value (sats)" type="number" value={builderData.prevValue} onChange={(e) => setBuilderData({ ...builderData, prevValue: e.target.value })} data-testid="input-prev-value" />
                  <Input placeholder="Previous Script (hex)" value={builderData.prevScriptHex} onChange={(e) => setBuilderData({ ...builderData, prevScriptHex: e.target.value })} data-testid="input-prev-script" />
                  <Input placeholder="Destination Value (sats)" type="number" value={builderData.destValue} onChange={(e) => setBuilderData({ ...builderData, destValue: e.target.value })} data-testid="input-dest-value" />
                </div>
                <Input placeholder="Destination Script (hex)" value={builderData.destScriptHex} onChange={(e) => setBuilderData({ ...builderData, destScriptHex: e.target.value })} data-testid="input-dest-script" />
                <Button onClick={buildAndSign} disabled={buildLoading} className="w-full">
                  {buildLoading ? "Building..." : "Build & Sign Transaction"}
                </Button>

                {builtTx && (
                  <div className="space-y-6">
                    {/* Original Transaction */}
                    <div className="space-y-2 border-t pt-6">
                      <h4 className="font-semibold text-sm">Original Signed Transaction</h4>
                      <div>
                        <label className="text-xs text-muted-foreground">Transaction ID:</label>
                        <Button size="sm" variant="outline" onClick={() => copyToClipboard(builtTx.txId)} data-testid="button-copy-txid" className="ml-2 mb-2">
                          <Copy className="w-4 h-4 mr-2" /> Copy
                        </Button>
                        <code className="block bg-muted p-2 rounded font-mono text-xs break-all">{builtTx.txId}</code>
                      </div>
                      <div className="mt-2">
                        <label className="text-xs text-muted-foreground">Transaction Hex:</label>
                        <Button size="sm" variant="outline" onClick={() => copyToClipboard(builtTx.txHex)} data-testid="button-copy-signed-hex" className="ml-2 mb-2">
                          <Copy className="w-4 h-4 mr-2" /> Copy
                        </Button>
                        <Textarea value={builtTx.txHex} readOnly rows={4} className="font-mono text-xs" />
                      </div>
                    </div>

                    {/* DER Malleability Variants */}
                    {builtTx.mutations && builtTx.mutations.length > 0 && (
                      <div className="space-y-4 border-t pt-6">
                        <div>
                          <h4 className="font-semibold text-sm mb-4">DER Malleability Variants ({builtTx.mutations.length})</h4>
                          <p className="text-xs text-muted-foreground mb-4">These are signature variants that maintain cryptographic validity but demonstrate malleability vulnerabilities:</p>
                        </div>
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
                            <div className="space-y-1">
                              <label className="text-xs text-muted-foreground block">Original:</label>
                              <code className="block bg-muted p-2 rounded font-mono text-xs break-all leading-tight">{mut.original}</code>
                            </div>
                            <div className="space-y-1">
                              <label className="text-xs text-muted-foreground block">Mutated:</label>
                              <code className="block bg-muted p-2 rounded font-mono text-xs break-all leading-tight">{mut.mutated}</code>
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
        </Tabs>
      </div>
    </div>
  );
}
