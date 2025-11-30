import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function Cve42461Panel() {
  const [libraryName, setLibraryName] = useState("elliptic@6.5.x");
  const [msgHashHex, setMsgHashHex] = useState("");
  const [derHex, setDerHex] = useState("");
  const [pubkeyHex, setPubkeyHex] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    setError(null);
    setResult(null);

    if (!msgHashHex || !derHex || !pubkeyHex) {
      setError("Fill msg hash, DER signature, and pubkey.");
      return;
    }

    try {
      setLoading(true);
      const response = await fetch("/api/cve42461", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          libraryName,
          curve: "secp256k1",
          msgHashHex: msgHashHex.trim(),
          canonicalDerHex: derHex.trim(),
          pubkeyHex: pubkeyHex.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const report = await response.json();
      setResult(report);
    } catch (e: any) {
      setError(e.message || "Error running CVE suite");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card data-testid="cve42461-panel">
      <CardHeader>
        <CardTitle>CVE-2024-42461 Library Check</CardTitle>
        <CardDescription>Test library for non-canonical DER acceptance</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <label className="text-sm font-medium" htmlFor="library-select">
            Library
          </label>
          <Select value={libraryName} onValueChange={setLibraryName}>
            <SelectTrigger id="library-select" data-testid="library-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="elliptic@6.5.x">elliptic@6.5.x</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div>
          <label className="text-sm font-medium" htmlFor="msg-hash">
            Message Hash (hex)
          </label>
          <Input
            id="msg-hash"
            data-testid="input-msg-hash"
            value={msgHashHex}
            onChange={(e) => setMsgHashHex(e.target.value)}
            placeholder="32-byte SHA256 hash"
          />
        </div>

        <div>
          <label className="text-sm font-medium" htmlFor="der-sig">
            Canonical DER Signature (hex)
          </label>
          <Textarea
            id="der-sig"
            data-testid="textarea-der-sig"
            rows={3}
            value={derHex}
            onChange={(e) => setDerHex(e.target.value)}
            placeholder="DER-encoded signature"
          />
        </div>

        <div>
          <label className="text-sm font-medium" htmlFor="pubkey">
            Public Key (hex)
          </label>
          <Input
            id="pubkey"
            data-testid="input-pubkey"
            value={pubkeyHex}
            onChange={(e) => setPubkeyHex(e.target.value)}
            placeholder="Compressed pubkey"
          />
        </div>

        <Button disabled={loading} onClick={handleRun} data-testid="button-run-cve">
          {loading ? "Running tests…" : "Run BER/DER Tests"}
        </Button>

        {error && <div className="text-destructive text-sm" data-testid="error-cve">{error}</div>}

        {result && (
          <div className="space-y-4" data-testid="result-cve">
            <h3 className="font-semibold">Result for {result.libraryName}</h3>
            <div>
              <p>
                Canonical accepted:{" "}
                {result.acceptsCanonicalDER ? "✅" : "❌ (broken implementation)"}
              </p>
              <p>
                Non-canonical BER accepted:{" "}
                {result.acceptsBERVariants ? "❌ vulnerable" : "✅ safe"}
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full border-collapse border border-gray-300 text-sm">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="border border-gray-300 px-2 py-1">Id</th>
                    <th className="border border-gray-300 px-2 py-1">Encoding</th>
                    <th className="border border-gray-300 px-2 py-1">Should Verify</th>
                    <th className="border border-gray-300 px-2 py-1">Did Verify</th>
                    <th className="border border-gray-300 px-2 py-1">Error</th>
                  </tr>
                </thead>
                <tbody>
                  {result.testCases.map((tc: any) => (
                    <tr key={tc.id} data-testid={`row-test-${tc.id}`}>
                      <td className="border border-gray-300 px-2 py-1">{tc.id}</td>
                      <td className="border border-gray-300 px-2 py-1">{tc.encodingType}</td>
                      <td className="border border-gray-300 px-2 py-1">{String(tc.shouldVerify)}</td>
                      <td className="border border-gray-300 px-2 py-1">{String(tc.didVerify)}</td>
                      <td className="border border-gray-300 px-2 py-1 text-xs">{tc.error || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
