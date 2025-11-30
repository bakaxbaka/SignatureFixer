import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function WycheproofLab() {
  const [curve, setCurve] = useState<"secp256k1" | "secp521r1">("secp256k1");
  const [libraryName, setLibraryName] = useState("elliptic");
  const [filterMode, setFilterMode] = useState<"all" | "edge">("edge");
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    setError(null);
    setSummary(null);

    try {
      setLoading(true);

      const response = await fetch("/api/wycheproof", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          curve,
          libraryName,
          filterMode,
        }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const summaryResult = await response.json();
      setSummary(summaryResult);
    } catch (e: any) {
      setError(e.message || "Wycheproof run failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card data-testid="wycheproof-lab">
      <CardHeader>
        <CardTitle>Wycheproof Test Lab</CardTitle>
        <CardDescription>Run Google Wycheproof ECDSA test vectors</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="text-sm font-medium" htmlFor="curve-select">
              Curve
            </label>
            <Select value={curve} onValueChange={(val) => setCurve(val as any)}>
              <SelectTrigger id="curve-select" data-testid="curve-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="secp256k1">secp256k1 (Bitcoin)</SelectItem>
                <SelectItem value="secp521r1">secp521r1</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <label className="text-sm font-medium" htmlFor="lib-select">
              Library
            </label>
            <Select value={libraryName} onValueChange={setLibraryName}>
              <SelectTrigger id="lib-select" data-testid="lib-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="elliptic">elliptic</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <label className="text-sm font-medium" htmlFor="filter-select">
              Filter
            </label>
            <Select value={filterMode} onValueChange={(val) => setFilterMode(val as any)}>
              <SelectTrigger id="filter-select" data-testid="filter-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All test vectors</SelectItem>
                <SelectItem value="edge">Only edge-case / malformed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <Button disabled={loading} onClick={handleRun} data-testid="button-run-wycheproof">
          {loading ? "Running Wycheproof…" : "Run Wycheproof Suite"}
        </Button>

        {error && <div className="text-destructive text-sm" data-testid="error-wycheproof">{error}</div>}

        {summary && (
          <div className="space-y-4" data-testid="result-wycheproof">
            <h3 className="font-semibold">
              {summary.libraryName} on {summary.curve}
            </h3>
            <p>
              Passed {summary.passed} / {summary.total}, failed {summary.failed}
            </p>

            {summary.mismatches.length > 0 && (
              <>
                <h4 className="font-medium">Mismatches</h4>
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse border border-gray-300 text-sm">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="border border-gray-300 px-2 py-1">tcId</th>
                        <th className="border border-gray-300 px-2 py-1">Expected</th>
                        <th className="border border-gray-300 px-2 py-1">Lib Accepts</th>
                        <th className="border border-gray-300 px-2 py-1">Parser Accepts</th>
                        <th className="border border-gray-300 px-2 py-1">Flags</th>
                        <th className="border border-gray-300 px-2 py-1">DER Issues</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.mismatches.map((m: any) => (
                        <tr key={m.tcId} data-testid={`row-mismatch-${m.tcId}`}>
                          <td className="border border-gray-300 px-2 py-1">{m.tcId}</td>
                          <td className="border border-gray-300 px-2 py-1">{m.expected}</td>
                          <td className="border border-gray-300 px-2 py-1">{String(m.libraryAccepts)}</td>
                          <td className="border border-gray-300 px-2 py-1">{String(m.parserAccepts)}</td>
                          <td className="border border-gray-300 px-2 py-1 text-xs">{m.flags.join(", ")}</td>
                          <td className="border border-gray-300 px-2 py-1 text-xs">{m.derIssues.join("; ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
