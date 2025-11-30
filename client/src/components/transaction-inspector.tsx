import React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertTriangle, CheckCircle, Copy } from "lucide-react";
import { parseRawTx, calculateWeight, analyzeDERSignatures, generateTags, parseInputs, parseOutputs, getPubkeyMap, getRValueMap } from "@/lib/transaction-analyzer";
import { truncateString, formatBTC } from "@/lib/bitcoin-utils";
import { useToast } from "@/hooks/use-toast";

interface TransactionInspectorProps {
  txHex: string;
  txid?: string;
}

export function TransactionInspector({ txHex, txid }: TransactionInspectorProps) {
  const { toast } = useToast();
  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({ description: `${label} copied to clipboard` });
  };

  try {
    const txInfo = parseRawTx(txHex);
    const { vsize, weight } = calculateWeight(txHex);
    const derAnalysis = analyzeDERSignatures(txHex);
    const tags = generateTags(derAnalysis);
    const inputs = parseInputs(txHex, txInfo.isSegwit);
    const pubkeyMap = getPubkeyMap(inputs);
    const rValueMap = getRValueMap(inputs);

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
            <div className="space-y-4">
              {inputs.filter(input => input.signature).length === 0 ? (
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>No signatures found in this transaction (SegWit witness data not shown).</AlertDescription>
                </Alert>
              ) : (
                inputs.map((input, idx) => (
                  input.signature && (
                    <Card key={idx} className="border-purple-500/20 bg-purple-500/5">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <CardTitle className="text-base">Input #{input.index}</CardTitle>
                          <Badge variant="outline">{input.scriptType}</Badge>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {/* DER Section */}
                        <div className="border rounded p-3 bg-muted/30">
                          <div className="flex items-center justify-between mb-2">
                            <p className="text-xs font-semibold text-muted-foreground">DER Signature</p>
                            <button
                              onClick={() => copyToClipboard(input.signature!.der, "DER")}
                              className="p-1 hover:bg-muted rounded"
                              title="Copy DER"
                            >
                              <Copy className="w-3 h-3" />
                            </button>
                          </div>
                          <code className="block font-mono text-xs break-all text-purple-600 dark:text-purple-400">
                            {input.signature.der}
                          </code>
                        </div>

                        {/* r, s, sighash grid */}
                        <div className="grid grid-cols-3 gap-3 text-xs">
                          <div className="border rounded p-2">
                            <p className="text-muted-foreground mb-1">r</p>
                            <code className="font-mono text-xs break-all">{truncateString(input.signature.r, 8, 4)}</code>
                          </div>
                          <div className="border rounded p-2">
                            <p className="text-muted-foreground mb-1">s</p>
                            <code className="font-mono text-xs break-all">{truncateString(input.signature.s, 8, 4)}</code>
                          </div>
                          <div className="border rounded p-2">
                            <p className="text-muted-foreground mb-1">Sighash</p>
                            <code className="font-mono text-xs">{input.signature.sighashType}</code>
                          </div>
                        </div>

                        {/* Pubkey & Z-hash */}
                        <div className="grid grid-cols-2 gap-3 text-xs">
                          <div className="border rounded p-2">
                            <p className="text-muted-foreground mb-1">Pubkey</p>
                            <code className="font-mono text-xs break-all">{input.pubkey ? truncateString(input.pubkey, 8, 4) : "—"}</code>
                          </div>
                          <div className="border rounded p-2">
                            <p className="text-muted-foreground mb-1">Z-Hash</p>
                            <code className="font-mono text-xs break-all">{truncateString(input.signature.zHash, 8, 4)}</code>
                          </div>
                        </div>

                        {/* Flags */}
                        <div className="space-y-2">
                          <p className="text-xs font-semibold">Flags</p>
                          <div className="flex flex-wrap gap-2">
                            {input.signature.isHighS ? (
                              <Badge className="bg-amber-600">⚠ High-S</Badge>
                            ) : (
                              <Badge className="bg-green-600">✓ Low-S</Badge>
                            )}
                            {input.signature.isCanonical ? (
                              <Badge className="bg-green-600">✓ Canonical DER</Badge>
                            ) : (
                              <Badge className="bg-red-600">⚠ Non-canonical</Badge>
                            )}
                            {!input.signature.isRValid ? (
                              <Badge className="bg-red-600">⚠ r out of range</Badge>
                            ) : null}
                            {!input.signature.isSValid ? (
                              <Badge className="bg-red-600">⚠ s out of range</Badge>
                            ) : null}
                          </div>
                        </div>

                        {/* Cross-references */}
                        {input.pubkey && pubkeyMap.get(input.pubkey)!.length > 1 && (
                          <Alert className="bg-blue-500/10 border-blue-500/20">
                            <CheckCircle className="h-4 w-4 text-blue-600" />
                            <AlertDescription className="text-xs">
                              This pubkey also signs inputs: {pubkeyMap.get(input.pubkey)!.filter(i => i !== input.index).map(i => `#${i}`).join(", ")}
                            </AlertDescription>
                          </Alert>
                        )}

                        {input.signature.r && rValueMap.get(input.signature.r)!.length > 1 && (
                          <Alert className="bg-red-500/10 border-red-500/20">
                            <AlertTriangle className="h-4 w-4 text-red-600" />
                            <AlertDescription className="text-xs">
                              ⚠ r value collision: also used in input(s) {rValueMap.get(input.signature.r)!.filter(i => i !== input.index).map(i => `#${i}`).join(", ")}
                            </AlertDescription>
                          </Alert>
                        )}
                      </CardContent>
                    </Card>
                  )
                ))
              )}
            </div>
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
