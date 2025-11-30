import React, { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Copy, Plus, Trash2, Eye, Loader2, ChevronDown, Send } from "lucide-react";

interface TxInput {
  txid: string;
  vout: number;
  sequence: number;
  scriptSig: string;
  value?: number;
}

interface TxOutput {
  value: number;
  scriptPubKey: string;
  address?: string;
}

interface UTXO {
  txid: string;
  vout: number;
  value: number;
  scriptPubKey: string;
  confirmed: boolean;
  address?: string;
}

export default function RawTxBuilder() {
  const { toast } = useToast();
  const [addressInput, setAddressInput] = useState("");
  const [utxos, setUtxos] = useState<UTXO[]>([]);
  const [utxosLoading, setUtxosLoading] = useState(false);
  const [showUtxos, setShowUtxos] = useState(false);
  
  const [version, setVersion] = useState("02");
  const [inputs, setInputs] = useState<TxInput[]>([
    { txid: "", vout: 0, sequence: 0xfffffffe, scriptSig: "" }
  ]);
  const [outputs, setOutputs] = useState<TxOutput[]>([
    { value: 0, scriptPubKey: "" }
  ]);
  const [locktime, setLocktime] = useState("00000000");
  const [useSegwit, setUseSegwit] = useState(true);
  const [builtTxHex, setBuiltTxHex] = useState("");
  const [broadcastResult, setBroadcastResult] = useState<any>(null);
  const [broadcastLoading, setBroadcastLoading] = useState(false);

  const fetchUtxos = async () => {
    if (!addressInput.trim()) {
      toast({ title: "Error", description: "Enter Bitcoin address", variant: "destructive" });
      return;
    }
    setUtxosLoading(true);
    try {
      const res = await fetch("/api/get-utxos", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: addressInput }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed");
      setUtxos(data.data.utxos);
      setShowUtxos(true);
      toast({ title: "Success", description: `Found ${data.data.count} UTXOs` });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setUtxosLoading(false);
    }
  };

  const addUtxoAsInput = (utxo: UTXO) => {
    setInputs([...inputs, {
      txid: utxo.txid,
      vout: utxo.vout,
      sequence: 0xfffffffe,
      scriptSig: utxo.scriptPubKey || "",
      value: utxo.value,
    }]);
    toast({ title: "Added", description: `Input added: ${utxo.txid.slice(0, 16)}...` });
  };

  const txSize = useMemo(() => {
    let size = 4;
    if (useSegwit) size += 2;
    size += 1;
    inputs.forEach(inp => {
      size += 32 + 4 + 1 + (inp.scriptSig.length / 2) + 4;
    });
    size += 1;
    outputs.forEach(out => {
      size += 8 + 1 + (out.scriptPubKey.length / 2);
    });
    size += 4;
    return size;
  }, [inputs, outputs, useSegwit]);

  const estimatedFee = txSize * 1;
  const totalInputValue = useMemo(() => inputs.reduce((sum, inp) => sum + (inp.value || 0), 0), [inputs]);
  const totalOutputValue = useMemo(() => outputs.reduce((sum, out) => sum + out.value, 0), [outputs]);

  const addInput = () => setInputs([...inputs, { txid: "", vout: 0, sequence: 0xfffffffe, scriptSig: "" }]);
  const removeInput = (idx: number) => { if (inputs.length > 1) setInputs(inputs.filter((_, i) => i !== idx)); };
  const addOutput = () => setOutputs([...outputs, { value: 0, scriptPubKey: "" }]);
  const removeOutput = (idx: number) => { if (outputs.length > 1) setOutputs(outputs.filter((_, i) => i !== idx)); };
  const updateInput = (idx: number, field: keyof TxInput, value: any) => {
    const newInputs = [...inputs];
    newInputs[idx][field] = value;
    setInputs(newInputs);
  };
  const updateOutput = (idx: number, field: keyof TxOutput, value: any) => {
    const newOutputs = [...outputs];
    newOutputs[idx][field] = value;
    setOutputs(newOutputs);
  };

  const buildTxHex = () => {
    try {
      let hex = version;
      if (useSegwit) hex += "0001";
      hex += inputs.length.toString(16).padStart(2, "0");
      inputs.forEach(inp => {
        hex += inp.txid;
        hex += inp.vout.toString(16).padStart(8, "0");
        hex += inp.scriptSig.length / 2 > 0 
          ? (inp.scriptSig.length / 2).toString(16).padStart(2, "0") + inp.scriptSig 
          : "00";
        hex += inp.sequence.toString(16).padStart(8, "0");
      });
      hex += outputs.length.toString(16).padStart(2, "0");
      outputs.forEach(out => {
        hex += out.value.toString(16).padStart(16, "0");
        hex += out.scriptPubKey.length / 2 > 0
          ? (out.scriptPubKey.length / 2).toString(16).padStart(2, "0") + out.scriptPubKey
          : "00";
      });
      hex += locktime;
      setBuiltTxHex(hex);
      toast({ title: "Success", description: "Transaction built" });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    }
  };

  // One-click broadcast
  const broadcastTx = async () => {
    if (!builtTxHex) {
      toast({ title: "Error", description: "Build a transaction first", variant: "destructive" });
      return;
    }
    setBroadcastLoading(true);
    try {
      const res = await fetch("/api/broadcast-tx", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ txHex: builtTxHex }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Broadcast failed");
      setBroadcastResult(data.data);
      toast({ title: "Success", description: `Broadcasting complete! TXID: ${data.data.txid}` });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
    } finally {
      setBroadcastLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied" });
  };

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-4xl font-bold">Raw Transaction Builder</h1>
          <p className="text-muted-foreground mt-2">Build, sign & broadcast Bitcoin transactions</p>
        </div>

        {/* UTXO Selector */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Select Inputs from Address</CardTitle>
            <CardDescription>Enter a Bitcoin address to fetch available UTXOs</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input placeholder="Bitcoin address" value={addressInput} onChange={(e) => setAddressInput(e.target.value)} className="flex-1" />
              <Button onClick={fetchUtxos} disabled={utxosLoading}>
                {utxosLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Fetch UTXOs"}
              </Button>
            </div>

            {showUtxos && utxos.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium">Available UTXOs ({utxos.length})</p>
                  <Button size="sm" variant="outline" onClick={() => setShowUtxos(!showUtxos)}>
                    <ChevronDown className="w-4 h-4" />
                  </Button>
                </div>
                {showUtxos && (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {utxos.map((utxo, idx) => (
                      <div key={idx} className="flex items-center justify-between border rounded p-3 bg-muted/30">
                        <div className="space-y-1 flex-1">
                          <p className="text-xs font-mono">{utxo.txid.slice(0, 20)}:{utxo.vout}</p>
                          <div className="flex gap-2">
                            <Badge variant="outline">{utxo.value} sat</Badge>
                            {utxo.confirmed ? (
                              <Badge variant="default">Confirmed</Badge>
                            ) : (
                              <Badge variant="secondary">Unconfirmed</Badge>
                            )}
                          </div>
                        </div>
                        <Button size="sm" onClick={() => addUtxoAsInput(utxo)}>
                          <Plus className="w-4 h-4 mr-1" /> Use
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-4 mb-8">
          <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">TX Size</p><p className="text-xl font-bold">{txSize} B</p></CardContent></Card>
          <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Fee Est.</p><p className="text-xl font-bold">{estimatedFee} sat</p></CardContent></Card>
          <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Input Val</p><p className="text-xl font-bold">{totalInputValue} sat</p></CardContent></Card>
          <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Output Val</p><p className="text-xl font-bold">{totalOutputValue} sat</p></CardContent></Card>
          <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Change</p><p className={`text-xl font-bold ${totalInputValue >= totalOutputValue ? 'text-green-500' : 'text-red-500'}`}>{totalInputValue - totalOutputValue} sat</p></CardContent></Card>
        </div>

        {/* TX Settings */}
        <Card className="mb-8">
          <CardHeader><CardTitle>Transaction Settings</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <Input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Version" />
              <Input value={locktime} onChange={(e) => setLocktime(e.target.value)} placeholder="Locktime" />
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={useSegwit} onChange={(e) => setUseSegwit(e.target.checked)} />
              <span className="text-sm">Use SegWit</span>
            </label>
          </CardContent>
        </Card>

        {/* Inputs */}
        <Card className="mb-8">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Inputs ({inputs.length})</CardTitle>
            <Button size="sm" onClick={addInput}><Plus className="w-4 h-4 mr-2" /> Add</Button>
          </CardHeader>
          <CardContent className="space-y-4">
            {inputs.map((inp, idx) => (
              <div key={idx} className="border rounded p-4 space-y-3 bg-muted/30">
                <div className="flex justify-between items-center">
                  <p className="font-medium text-sm">Input #{idx}{inp.value && ` (${inp.value} sat)`}</p>
                  <Button size="sm" variant="destructive" onClick={() => removeInput(idx)} disabled={inputs.length === 1}>
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
                <Input placeholder="TXID" value={inp.txid} onChange={(e) => updateInput(idx, "txid", e.target.value)} className="font-mono text-xs" />
                <div className="grid grid-cols-2 gap-2">
                  <Input placeholder="Vout" type="number" value={inp.vout} onChange={(e) => updateInput(idx, "vout", parseInt(e.target.value))} />
                  <Input placeholder="Sequence" value={inp.sequence.toString(16)} onChange={(e) => updateInput(idx, "sequence", parseInt(e.target.value, 16))} />
                </div>
                <Input placeholder="ScriptSig (hex)" value={inp.scriptSig} onChange={(e) => updateInput(idx, "scriptSig", e.target.value)} className="font-mono text-xs" />
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Outputs */}
        <Card className="mb-8">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Outputs ({outputs.length})</CardTitle>
            <Button size="sm" onClick={addOutput}><Plus className="w-4 h-4 mr-2" /> Add</Button>
          </CardHeader>
          <CardContent className="space-y-4">
            {outputs.map((out, idx) => (
              <div key={idx} className="border rounded p-4 space-y-3 bg-muted/30">
                <div className="flex justify-between items-center">
                  <p className="font-medium text-sm">Output #{idx}</p>
                  <Button size="sm" variant="destructive" onClick={() => removeOutput(idx)} disabled={outputs.length === 1}>
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
                <Input placeholder="Value (satoshis)" type="number" value={out.value} onChange={(e) => updateOutput(idx, "value", parseInt(e.target.value))} />
                <Input placeholder="ScriptPubKey (hex)" value={out.scriptPubKey} onChange={(e) => updateOutput(idx, "scriptPubKey", e.target.value)} className="font-mono text-xs" />
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Build & Broadcast */}
        <div className="flex gap-2 mb-8">
          <Button onClick={buildTxHex} className="flex-1">Build Transaction</Button>
          <Button onClick={broadcastTx} disabled={!builtTxHex || broadcastLoading} variant="default" className="flex-1 bg-green-600 hover:bg-green-700">
            {broadcastLoading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Broadcasting...
              </>
            ) : (
              <>
                <Send className="w-4 h-4 mr-2" />
                Broadcast to Blockchain
              </>
            )}
          </Button>
        </div>

        {/* Built Transaction */}
        {builtTxHex && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Built Transaction Hex</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button size="sm" onClick={() => copyToClipboard(builtTxHex)}>
                <Copy className="w-4 h-4 mr-2" /> Copy Hex
              </Button>
              <Textarea value={builtTxHex} readOnly rows={4} className="font-mono text-xs" />
            </CardContent>
          </Card>
        )}

        {/* Broadcast Result */}
        {broadcastResult && (
          <Card className="border-green-500 bg-green-50/10">
            <CardHeader>
              <CardTitle className="text-green-600">Transaction Broadcast Successfully!</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground">Transaction ID (TXID):</p>
                <div className="flex items-center gap-2 mt-2">
                  <code className="block bg-muted p-2 rounded font-mono text-xs break-all flex-1">{broadcastResult.txid}</code>
                  <Button size="sm" onClick={() => copyToClipboard(broadcastResult.txid)}>
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Broadcast Endpoint:</p>
                <Badge className="mt-2">{broadcastResult.endpoint}</Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                Your transaction has been broadcast to the Bitcoin network and should appear on block explorers within a few moments.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
