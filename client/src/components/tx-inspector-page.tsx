import React, { useState } from "react";
import type {
  InspectTxResponse,
  TxInputAnalysis,
  TxOutputAnalysis,
  SignatureAnalysis,
} from "@/types/txInspector";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertTriangle, CheckCircle, Copy } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface TxInspectorPageProps {
  initialTxid?: string;
  initialRawTxHex?: string;
}

export function TxInspectorPage({
  initialTxid = "",
  initialRawTxHex = "",
}: TxInspectorPageProps) {
  const { toast } = useToast();
  const [inputMode, setInputMode] = useState<"auto" | "txid" | "raw">("auto");
  const [inputValue, setInputValue] = useState(initialRawTxHex || initialTxid || "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InspectTxResponse | null>(null);

  function detectMode(value: string): "txid" | "raw" {
    const trimmed = value.trim();
    const isHex = /^[0-9a-fA-F]+$/.test(trimmed);

    if (isHex && trimmed.length === 64) return "txid";
    if (isHex && trimmed.length > 64) return "raw";
    return "raw";
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);

    const trimmed = inputValue.trim();
    if (!trimmed) {
      setError("Please paste a txid or raw transaction hex.");
      return;
    }

    const mode = inputMode === "auto" ? detectMode(trimmed) : inputMode;
    const body =
      mode === "txid" ? { txid: trimmed } : { rawTxHex: trimmed.toLowerCase() };

    try {
      setLoading(true);

      const res = await fetch("/api/inspect-tx", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const json: InspectTxResponse = await res.json();
      if (!json.ok) {
        setError(json.error || "Unknown error from inspector.");
      } else {
        setResult(json);
      }
    } catch (err: any) {
      setError(err.message || "Network error while calling /api/inspect-tx.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">Transaction Inspector</h1>
        <p className="text-muted-foreground">
          Paste a Bitcoin transaction ID or raw hex to analyze it end-to-end
        </p>
      </div>

      {/* INPUT PANEL */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Input Transaction</CardTitle>
          <CardDescription>Paste a 64-char txid or full transaction hex</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <textarea
                data-testid="input-tx-hex"
                rows={5}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                placeholder="Paste a Bitcoin txid (64 hex chars) or raw transaction hex here…"
                className="w-full p-3 border rounded-lg font-mono text-sm bg-muted/30 focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>

            <div className="flex flex-col md:flex-row gap-4 items-start md:items-end justify-between">
              <div className="flex items-center gap-4">
                <span className="text-sm font-medium">Interpret as:</span>
                <div className="flex gap-3">
                  {(["auto", "txid", "raw"] as const).map((mode) => (
                    <label key={mode} className="flex items-center gap-2">
                      <input
                        type="radio"
                        name="mode"
                        value={mode}
                        checked={inputMode === mode}
                        onChange={() => setInputMode(mode)}
                        className="cursor-pointer"
                      />
                      <span className="text-sm capitalize">{mode}</span>
                    </label>
                  ))}
                </div>
              </div>

              <Button
                type="submit"
                disabled={loading}
                data-testid="button-inspect-tx"
              >
                {loading ? "Inspecting…" : "Inspect Transaction"}
              </Button>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </form>
        </CardContent>
      </Card>

      {/* RESULT PANEL */}
      {result && result.ok && result.txid && (
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="grid w-full grid-cols-3 lg:w-auto">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="inputs">Inputs</TabsTrigger>
            <TabsTrigger value="outputs">Outputs</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <OverviewCard result={result} copyToClipboard={(text, label) => {
              navigator.clipboard.writeText(text);
              toast({ description: `${label} copied` });
            }} />
          </TabsContent>

          <TabsContent value="inputs">
            <InputsCard inputs={result.inputs || []} />
          </TabsContent>

          <TabsContent value="outputs">
            <OutputsCard outputs={result.outputs || []} />
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

// COMPONENTS

interface OverviewCardProps {
  result: InspectTxResponse;
  copyToClipboard: (text: string, label: string) => void;
}

function OverviewCard({ result, copyToClipboard }: OverviewCardProps) {
  const flags = result.summaryFlags;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Transaction Overview</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* TXID */}
        <div>
          <p className="text-sm font-medium mb-2">Transaction ID</p>
          <div className="flex items-center gap-2">
            <code data-testid="text-txid" className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">
              {result.txid}
            </code>
            <Button
              size="sm"
              variant="outline"
              onClick={() => copyToClipboard(result.txid || "", "TXID")}
            >
              <Copy className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Core metrics grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: "Network", value: result.network || "unknown" },
            { label: "Version", value: result.version },
            { label: "Locktime", value: result.locktime },
            { label: "Size", value: `${result.sizeBytes} B` },
          ].map((metric) => (
            <div key={metric.label} className="border rounded-lg p-3">
              <p className="text-xs text-muted-foreground mb-1">{metric.label}</p>
              <p data-testid={`metric-${metric.label.toLowerCase()}`} className="font-mono text-sm font-semibold">
                {metric.value}
              </p>
            </div>
          ))}
        </div>

        {/* Value summary */}
        <div className="grid grid-cols-3 gap-3">
          <div className="border rounded-lg p-3 bg-green-500/5">
            <p className="text-xs text-muted-foreground mb-1">Total In</p>
            <p data-testid="metric-total-input" className="font-mono font-semibold">
              {result.totalInputSats ?? "?"} sats
            </p>
          </div>
          <div className="border rounded-lg p-3 bg-orange-500/5">
            <p className="text-xs text-muted-foreground mb-1">Total Out</p>
            <p data-testid="metric-total-output" className="font-mono font-semibold">
              {result.totalOutputSats ?? "?"} sats
            </p>
          </div>
          <div className="border rounded-lg p-3 bg-red-500/5">
            <p className="text-xs text-muted-foreground mb-1">Fee Rate</p>
            <p data-testid="metric-feerate" className="font-mono font-semibold">
              {result.feeRateSatPerVbyte ?? "?"} sat/vB
            </p>
          </div>
        </div>

        {/* Signature health flags */}
        {flags && (
          <div className="border-t pt-4 space-y-2">
            <p className="font-semibold">Signature Health</p>
            <ul className="space-y-1 text-sm">
              {[
                {
                  flag: flags.hasHighS,
                  pass: "✅ Low-S only",
                  warn: "⚠️ High-S signatures present",
                },
                {
                  flag: flags.hasNonCanonicalDer,
                  pass: "✅ All signatures canonical DER",
                  warn: "⚠️ Non-canonical DER detected",
                },
                {
                  flag: flags.hasWeirdSighash,
                  pass: "✅ Standard SIGHASH_ALL only",
                  warn: "⚠️ Non-standard sighash types detected",
                },
                {
                  flag: flags.hasMultiInputSameKey,
                  pass: "✅ No multi-input same-key patterns",
                  warn: "⚠️ Multiple inputs share same pubkey",
                },
                {
                  flag: flags.hasRReuseWithinTx,
                  pass: "✅ No r-value reuse",
                  warn: "⚠️ r-value reuse within this tx",
                },
              ].map((item, i) => (
                <li key={i} className="flex items-center gap-2">
                  {item.flag ? item.warn : item.pass}
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface InputsCardProps {
  inputs: TxInputAnalysis[];
}

function InputsCard({ inputs }: InputsCardProps) {
  if (!inputs.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Inputs ({inputs.length})</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-semibold">#</th>
                <th className="text-left py-2 px-2 font-semibold">Prev Out</th>
                <th className="text-left py-2 px-2 font-semibold">Value</th>
                <th className="text-left py-2 px-2 font-semibold">Type</th>
                <th className="text-left py-2 px-2 font-semibold">Signature</th>
              </tr>
            </thead>
            <tbody>
              {inputs.map((inp) => (
                <tr key={inp.index} className="border-b hover:bg-muted/50">
                  <td data-testid={`row-input-${inp.index}`} className="py-2 px-2">
                    {inp.index}
                  </td>
                  <td className="py-2 px-2 font-mono text-xs">
                    {inp.prevTxid.slice(0, 16)}…:{inp.prevVout}
                  </td>
                  <td className="py-2 px-2">{inp.valueSats ?? "?"}</td>
                  <td className="py-2 px-2">
                    <Badge variant="outline" className="text-xs">
                      {inp.scriptType}
                    </Badge>
                  </td>
                  <td className="py-2 px-2">
                    {inp.signature ? (
                      <SignatureBadge sig={inp.signature} />
                    ) : inp.isCoinbase ? (
                      <span className="text-xs text-muted-foreground">Coinbase</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">No sig</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Signature details */}
        <div className="space-y-3 border-t pt-4">
          {inputs.map(
            (inp) =>
              inp.signature && (
                <SignatureDetailsExpanded
                  key={`sig-${inp.index}`}
                  index={inp.index}
                  sig={inp.signature}
                />
              )
          )}
        </div>
      </CardContent>
    </Card>
  );
}

interface SignatureBadgeProps {
  sig: SignatureAnalysis;
}

function SignatureBadge({ sig }: SignatureBadgeProps) {
  const issues = sig.derIssues.length + sig.warnings.length;
  return (
    <Badge variant={issues > 0 ? "destructive" : "default"} className="text-xs">
      {sig.sighashName} · {sig.isHighS ? "High-S" : "Low-S"}
      {issues > 0 && ` (${issues} issues)`}
    </Badge>
  );
}

interface SignatureDetailsExpandedProps {
  index: number;
  sig: SignatureAnalysis;
}

function SignatureDetailsExpanded({ index, sig }: SignatureDetailsExpandedProps) {
  return (
    <details className="border rounded-lg p-3 group">
      <summary className="cursor-pointer font-semibold flex items-center justify-between">
        <span>Input #{index} – Signature Details</span>
        <span className="group-open:rotate-180 transition-transform">▼</span>
      </summary>
      <div className="mt-3 space-y-3 text-sm">
        <div>
          <p className="font-medium mb-1">DER</p>
          <code data-testid={`text-der-${index}`} className="block p-2 bg-muted rounded font-mono text-xs break-all">
            {sig.derHex}
          </code>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {[
            { label: "r", value: sig.rHex },
            { label: "s", value: sig.sHex },
            { label: "z", value: sig.zHex },
            { label: "SIGHASH", value: `${sig.sighashName} (0x${sig.sighashType.toString(16)})` },
          ].map((item) => (
            <div key={item.label}>
              <p className="font-medium mb-1">{item.label}</p>
              <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                {item.value}
              </code>
            </div>
          ))}
        </div>

        {sig.pubkeyHex && (
          <div>
            <p className="font-medium mb-1">Pubkey</p>
            <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
              {sig.pubkeyHex}
            </code>
          </div>
        )}

        {(sig.derIssues.length > 0 || sig.warnings.length > 0) && (
          <div className="border-t pt-2">
            <p className="font-medium mb-1">Issues</p>
            <ul className="space-y-1 text-xs">
              {sig.derIssues.map((iss, i) => (
                <li key={`der-${i}`} className="flex items-start gap-2">
                  <span className="text-red-500">•</span>
                  <span>
                    <strong>[{iss.code}]</strong> {iss.message}
                  </span>
                </li>
              ))}
              {sig.warnings.map((w, i) => (
                <li key={`warn-${i}`} className="flex items-start gap-2">
                  <span className="text-yellow-500">•</span>
                  <span>{w}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </details>
  );
}

interface OutputsCardProps {
  outputs: TxOutputAnalysis[];
}

function OutputsCard({ outputs }: OutputsCardProps) {
  if (!outputs.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Outputs ({outputs.length})</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-semibold">#</th>
                <th className="text-left py-2 px-2 font-semibold">Value (sats)</th>
                <th className="text-left py-2 px-2 font-semibold">Address</th>
                <th className="text-left py-2 px-2 font-semibold">Type</th>
              </tr>
            </thead>
            <tbody>
              {outputs.map((out) => (
                <tr
                  key={out.index}
                  className={`border-b hover:bg-muted/50 ${
                    out.isChangeGuess ? "bg-green-500/5" : ""
                  }`}
                >
                  <td data-testid={`row-output-${out.index}`} className="py-2 px-2">
                    {out.index}
                  </td>
                  <td className="py-2 px-2 font-semibold">{out.valueSats}</td>
                  <td className="py-2 px-2 font-mono text-xs break-all">
                    {out.address ? out.address.slice(0, 20) + "…" : "—"}
                    {out.isChangeGuess && (
                      <Badge className="ml-2 text-xs" variant="secondary">
                        change?
                      </Badge>
                    )}
                  </td>
                  <td className="py-2 px-2">
                    <Badge variant="outline" className="text-xs">
                      {out.scriptType}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
