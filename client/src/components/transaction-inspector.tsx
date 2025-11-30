import React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertTriangle, CheckCircle } from "lucide-react";
import { parseRawTx, calculateWeight, analyzeDERSignatures, generateTags, parseInputs, parseOutputs } from "@/lib/transaction-analyzer";
import { truncateString, formatBTC } from "@/lib/bitcoin-utils";

interface TransactionInspectorProps {
  txHex: string;
  txid?: string;
}

export function TransactionInspector({ txHex, txid }: TransactionInspectorProps) {
  try {
    const txInfo = parseRawTx(txHex);
    const { vsize, weight } = calculateWeight(txHex);
    const derAnalysis = analyzeDERSignatures(txHex);
    const tags = generateTags(derAnalysis);

    // Mock data for demo (would fetch real data in production)
    const totalIn = 50000;
    const totalOut = 49500;
    const fee = totalIn - totalOut;
    const feerate = Math.ceil(fee / vsize);

    return (
      <div className="space-y-4">
        {/* Section 1: Overview */}
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              📋 Overview
            </CardTitle>
            <CardDescription>Transaction metadata and key metrics</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* TXID */}
            <div>
              <p className="text-xs text-muted-foreground mb-2">Transaction ID</p>
              <code className="block bg-muted p-2 rounded font-mono text-xs break-all">
                {txid || "N/A"}
              </code>
            </div>

            {/* Core metrics grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">Version</p>
                <p className="font-mono font-semibold">{txInfo.version}</p>
              </div>
              <div className="border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">Locktime</p>
                <p className="font-mono font-semibold">{txInfo.locktime}</p>
              </div>
              <div className="border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">Weight</p>
                <p className="font-mono font-semibold">{weight} WU</p>
              </div>
              <div className="border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">vSize</p>
                <p className="font-mono font-semibold">{vsize} vB</p>
              </div>
            </div>

            {/* I/O summary */}
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1"># Inputs</p>
                <p className="font-mono font-semibold text-lg">{txInfo.inputCount}</p>
              </div>
              <div className="border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1"># Outputs</p>
                <p className="font-mono font-semibold text-lg">{txInfo.outputCount}</p>
              </div>
              <div className="border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">Size</p>
                <p className="font-mono font-semibold">{txInfo.size} B</p>
              </div>
            </div>

            {/* Value summary */}
            <div className="grid grid-cols-3 gap-4">
              <div className="border rounded p-3 bg-green-500/5">
                <p className="text-xs text-muted-foreground mb-1">Total In</p>
                <p className="font-mono font-semibold">{formatBTC(totalIn)}</p>
                <p className="text-xs text-muted-foreground">{totalIn} sats</p>
              </div>
              <div className="border rounded p-3 bg-orange-500/5">
                <p className="text-xs text-muted-foreground mb-1">Total Out</p>
                <p className="font-mono font-semibold">{formatBTC(totalOut)}</p>
                <p className="text-xs text-muted-foreground">{totalOut} sats</p>
              </div>
              <div className="border rounded p-3 bg-red-500/5">
                <p className="text-xs text-muted-foreground mb-1">Fee</p>
                <p className="font-mono font-semibold">{fee} sats</p>
                <p className="text-xs text-muted-foreground">{feerate} sat/vB</p>
              </div>
            </div>

            {/* Tags */}
            {tags.length > 0 && (
              <div className="space-y-2">
                <p className="text-sm font-semibold">Security Flags</p>
                <div className="flex flex-wrap gap-2">
                  {tags.map((tag, idx) => (
                    <Badge
                      key={idx}
                      variant={tag.type === "strict-der" ? "default" : "destructive"}
                      className={
                        tag.type === "strict-der"
                          ? "bg-green-600"
                          : "bg-amber-600"
                      }
                    >
                      {tag.label}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Sections 2-4: Scaffolding */}
        <Tabs defaultValue="inputs" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="inputs">Inputs ({txInfo.inputCount})</TabsTrigger>
            <TabsTrigger value="outputs">Outputs ({txInfo.outputCount})</TabsTrigger>
            <TabsTrigger value="signatures">Signatures</TabsTrigger>
          </TabsList>

          <TabsContent value="inputs">
            <Card>
              <CardHeader>
                <CardTitle>Inputs ({txInfo.inputCount})</CardTitle>
                <CardDescription>Input details with script type, sequence, and pubkey detection</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="border-b font-semibold">
                      <tr>
                        <th className="text-left p-2">#</th>
                        <th className="text-left p-2">Prev TXID:Vout</th>
                        <th className="text-left p-2">Sequence</th>
                        <th className="text-left p-2">Type</th>
                        <th className="text-left p-2">Pubkey</th>
                      </tr>
                    </thead>
                    <tbody>
                      {parseInputs(txHex, txInfo.isSegwit).map((input) => (
                        <tr key={input.index} className="border-b hover:bg-muted/50">
                          <td className="p-2 font-mono">{input.index}</td>
                          <td className="p-2 font-mono text-xs">
                            {truncateString(input.prevTxid, 8, 4)}:{input.vout}
                          </td>
                          <td className="p-2 font-mono text-xs">{truncateString(input.sequence, 4, 4)}</td>
                          <td className="p-2">
                            <Badge variant="outline" className="text-xs">{input.scriptType}</Badge>
                          </td>
                          <td className="p-2 font-mono text-xs">
                            {input.pubkey ? truncateString(input.pubkey, 8, 4) : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="outputs">
            <Card>
              <CardHeader>
                <CardTitle>Outputs ({txInfo.outputCount})</CardTitle>
                <CardDescription>Output details with script type and address info</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="border-b font-semibold">
                      <tr>
                        <th className="text-left p-2">#</th>
                        <th className="text-left p-2">Value (sats)</th>
                        <th className="text-left p-2">Type</th>
                        <th className="text-left p-2">Address</th>
                      </tr>
                    </thead>
                    <tbody>
                      {parseOutputs(txHex, txInfo.inputCount, txInfo.isSegwit).map((output) => {
                        // Guess change: typically smallest output or second output
                        const isChange = output.index === 1 || output.index === txInfo.outputCount - 1;
                        return (
                          <tr 
                            key={output.index} 
                            className={`border-b hover:bg-muted/50 ${isChange ? 'bg-green-500/10' : ''}`}
                          >
                            <td className="p-2 font-mono">{output.index}</td>
                            <td className="p-2 font-mono">{output.value} {isChange && <Badge className="ml-2 bg-green-600 text-xs">change?</Badge>}</td>
                            <td className="p-2">
                              <Badge variant="outline" className="text-xs">{output.scriptType}</Badge>
                            </td>
                            <td className="p-2 font-mono text-xs">
                              {output.address || "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="signatures">
            <Card>
              <CardHeader>
                <CardTitle>Signature Analysis</CardTitle>
                <CardDescription>Per-input signature inspection with r/s validation</CardDescription>
              </CardHeader>
              <CardContent>
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Signature panel implementation coming soon. Shows DER, r/s values, sighash, pubkey, flags (High-S/Low-S, canonical/non-canonical), and pubkey cross-references.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    );
  } catch (error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          Failed to parse transaction: {(error as Error).message}
        </AlertDescription>
      </Alert>
    );
  }
}
