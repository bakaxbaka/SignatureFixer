import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Send, Loader2, Plus, Copy } from "lucide-react";

interface UTXO {
  txid: string;
  vout: number;
  value: number;
  confirmed: boolean;
}

export function QuickTxBuilder() {
  const { toast } = useToast();
  const [address, setAddress] = useState("");
  const [utxos, setUtxos] = useState<UTXO[]>([]);
  const [loading, setLoading] = useState(false);
  const [txHex, setTxHex] = useState("");
  const [broadcasting, setBroadcasting] = useState(false);
  const [result, setResult] = useState<any>(null);

  const fetchUtxos = async () => {
    if (!address.trim()) {
      toast({ title: "Error", description: "Enter Bitcoin address", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/get-utxos", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setUtxos(data.data.utxos);
      toast({ title: "Success", description: `Found ${data.data.count} UTXOs` });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const broadcast = async () => {
    if (!txHex.trim()) {
      toast({ title: "Error", description: "Paste transaction hex", variant: "destructive" });
      return;
    }
    setBroadcasting(true);
    try {
      const res = await fetch("/api/broadcast-tx", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ txHex }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setResult(data.data);
      toast({ title: "Success", description: "Transaction broadcast!" });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setBroadcasting(false);
    }
  };

  const copy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied" });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Transaction Broadcaster</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* UTXO Fetcher */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Bitcoin Address</label>
          <div className="flex gap-2">
            <Input placeholder="1..., 3..., bc1..." value={address} onChange={(e) => setAddress(e.target.value)} />
            <Button onClick={fetchUtxos} disabled={loading} size="sm">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4 mr-1" />}
              Fetch
            </Button>
          </div>
        </div>

        {/* UTXOs */}
        {utxos.length > 0 && (
          <div className="space-y-2">
            <label className="text-sm font-medium">Available UTXOs ({utxos.length})</label>
            <div className="max-h-40 overflow-y-auto space-y-2">
              {utxos.map((u, i) => (
                <div key={i} className="flex items-center justify-between border rounded p-2 bg-muted/30 text-xs">
                  <span className="font-mono">{u.txid.slice(0, 16)}:{u.vout}</span>
                  <div className="flex gap-2">
                    <Badge variant="outline">{u.value} sat</Badge>
                    {u.confirmed ? <Badge>✓</Badge> : <Badge variant="secondary">pending</Badge>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TX Hex */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Transaction Hex</label>
          <Textarea placeholder="Paste signed transaction hex..." value={txHex} onChange={(e) => setTxHex(e.target.value)} rows={3} className="font-mono text-xs" />
        </div>

        {/* Broadcast Button */}
        <Button onClick={broadcast} disabled={broadcasting || !txHex} className="w-full bg-green-600 hover:bg-green-700">
          {broadcasting ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Send className="w-4 h-4 mr-2" />}
          {broadcasting ? "Broadcasting..." : "Broadcast to Blockchain"}
        </Button>

        {/* Result */}
        {result && (
          <div className="border-t pt-4 space-y-2">
            <p className="text-sm font-medium text-green-600">✓ Broadcast Success!</p>
            <div className="flex items-center gap-2 bg-muted p-2 rounded">
              <code className="text-xs break-all flex-1">{result.txid}</code>
              <Button size="sm" variant="outline" onClick={() => copy(result.txid)}>
                <Copy className="w-3 h-3" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">Endpoint: <Badge>{result.endpoint}</Badge></p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
