import React, { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Copy, Plus, Trash2, Eye } from "lucide-react";

interface TxInput {
  txid: string;
  vout: number;
  sequence: number;
  scriptSig: string;
  witnessData?: string[];
}

interface TxOutput {
  value: number;
  scriptPubKey: string;
  address?: string;
}

export default function RawTxBuilder() {
  const { toast } = useToast();
  const [version, setVersion] = useState("02");
  const [inputs, setInputs] = useState<TxInput[]>([
    { txid: "", vout: 0, sequence: 0xfffffffe, scriptSig: "", witnessData: [] }
  ]);
  const [outputs, setOutputs] = useState<TxOutput[]>([
    { value: 0, scriptPubKey: "" }
  ]);
  const [locktime, setLocktime] = useState("00000000");
  const [useSegwit, setUseSegwit] = useState(true);
  const [showPreview, setShowPreview] = useState(false);
  const [builtTxHex, setBuiltTxHex] = useState("");

  // Calculate transaction size
  const txSize = useMemo(() => {
    let size = 4; // version
    if (useSegwit) size += 2; // marker + flag
    size += 1; // input count
    inputs.forEach(inp => {
      size += 32 + 4 + 1 + inp.scriptSig.length / 2 + 4; // txid + vout + script_len + script + sequence
    });
    size += 1; // output count
    outputs.forEach(out => {
      size += 8 + 1 + out.scriptPubKey.length / 2; // value + script_len + script
    });
    if (useSegwit) {
      inputs.forEach(inp => {
        size += 1; // witness item count
        if (inp.witnessData) {
          inp.witnessData.forEach(item => {
            size += 1 + item.length / 2;
          });
        }
      });
    }
    size += 4; // locktime
    return size;
  }, [inputs, outputs, useSegwit]);

  // Estimate fee
  const estimatedFee = useMemo(() => {
    const satPerByte = 1;
    return txSize * satPerByte;
  }, [txSize]);

  // Add input
  const addInput = () => {
    setInputs([...inputs, { txid: "", vout: 0, sequence: 0xfffffffe, scriptSig: "" }]);
  };

  // Remove input
  const removeInput = (idx: number) => {
    if (inputs.length > 1) {
      setInputs(inputs.filter((_, i) => i !== idx));
    }
  };

  // Add output
  const addOutput = () => {
    setOutputs([...outputs, { value: 0, scriptPubKey: "" }]);
  };

  // Remove output
  const removeOutput = (idx: number) => {
    if (outputs.length > 1) {
      setOutputs(outputs.filter((_, i) => i !== idx));
    }
  };

  // Update input
  const updateInput = (idx: number, field: keyof TxInput, value: any) => {
    const newInputs = [...inputs];
    newInputs[idx][field] = value;
    setInputs(newInputs);
  };

  // Update output
  const updateOutput = (idx: number, field: keyof TxOutput, value: any) => {
    const newOutputs = [...outputs];
    newOutputs[idx][field] = value;
    setOutputs(newOutputs);
  };

  // Build transaction hex
  const buildTxHex = () => {
    try {
      // Simple hex builder - this would need proper implementation
      let hex = version;
      
      if (useSegwit) {
        hex += "0001"; // marker + flag
      }

      // Input count
      hex += inputs.length.toString(16).padStart(2, "0");

      // Add inputs
      inputs.forEach(inp => {
        // Reverse txid for little-endian
        hex += inp.txid; // Should be reversed
        hex += inp.vout.toString(16).padStart(8, "0");
        hex += inp.scriptSig.length / 2 > 0 
          ? inp.scriptSig.length / 2 .toString(16).padStart(2, "0") + inp.scriptSig 
          : "00";
        hex += inp.sequence.toString(16).padStart(8, "0");
      });

      // Output count
      hex += outputs.length.toString(16).padStart(2, "0");

      // Add outputs
      outputs.forEach(out => {
        hex += out.value.toString(16).padStart(16, "0");
        hex += out.scriptPubKey.length / 2 > 0
          ? out.scriptPubKey.length / 2 .toString(16).padStart(2, "0") + out.scriptPubKey
          : "00";
      });

      // Locktime
      hex += locktime;

      setBuiltTxHex(hex);
      toast({ title: "Success", description: "Transaction built" });
    } catch (e) {
      toast({ title: "Error", description: (e as Error).message, variant: "destructive" });
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
          <p className="text-muted-foreground mt-2">Advanced transaction construction with multi-input/output support</p>
        </div>

        <div className="grid grid-cols-3 gap-4 mb-8">
          <Card>
            <CardContent className="p-4">
              <p className="text-sm text-muted-foreground">TX Size</p>
              <p className="text-2xl font-bold">{txSize} bytes</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <p className="text-sm text-muted-foreground">Estimated Fee (1 sat/byte)</p>
              <p className="text-2xl font-bold">{estimatedFee} sat</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <p className="text-sm text-muted-foreground">Inputs / Outputs</p>
              <p className="text-2xl font-bold">{inputs.length} / {outputs.length}</p>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          {/* Transaction Settings */}
          <Card>
            <CardHeader>
              <CardTitle>Transaction Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium">Version</label>
                  <Input value={version} onChange={(e) => setVersion(e.target.value)} />
                </div>
                <div>
                  <label className="text-sm font-medium">Locktime</label>
                  <Input value={locktime} onChange={(e) => setLocktime(e.target.value)} />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <input 
                  type="checkbox" 
                  checked={useSegwit} 
                  onChange={(e) => setUseSegwit(e.target.checked)}
                  id="segwit-toggle"
                />
                <label htmlFor="segwit-toggle" className="text-sm">Use SegWit (P2WPKH)</label>
              </div>
            </CardContent>
          </Card>

          {/* Inputs */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Inputs ({inputs.length})</CardTitle>
              <Button size="sm" onClick={addInput}>
                <Plus className="w-4 h-4 mr-2" /> Add Input
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              {inputs.map((inp, idx) => (
                <div key={idx} className="border rounded p-4 space-y-3 bg-muted/30">
                  <div className="flex items-center justify-between">
                    <p className="font-medium text-sm">Input #{idx}</p>
                    <Button 
                      size="sm" 
                      variant="destructive" 
                      onClick={() => removeInput(idx)}
                      disabled={inputs.length === 1}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Input 
                      placeholder="Previous TX ID" 
                      value={inp.txid} 
                      onChange={(e) => updateInput(idx, "txid", e.target.value)}
                      className="font-mono text-xs"
                    />
                    <Input 
                      placeholder="Output Index" 
                      type="number" 
                      value={inp.vout} 
                      onChange={(e) => updateInput(idx, "vout", parseInt(e.target.value))}
                    />
                  </div>
                  <Input 
                    placeholder="Script Sig (hex)" 
                    value={inp.scriptSig} 
                    onChange={(e) => updateInput(idx, "scriptSig", e.target.value)}
                    className="font-mono text-xs"
                  />
                  <Input 
                    placeholder="Sequence (hex)" 
                    value={inp.sequence.toString(16)} 
                    onChange={(e) => updateInput(idx, "sequence", parseInt(e.target.value, 16))}
                    className="font-mono text-xs"
                  />
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Outputs */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Outputs ({outputs.length})</CardTitle>
              <Button size="sm" onClick={addOutput}>
                <Plus className="w-4 h-4 mr-2" /> Add Output
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              {outputs.map((out, idx) => (
                <div key={idx} className="border rounded p-4 space-y-3 bg-muted/30">
                  <div className="flex items-center justify-between">
                    <p className="font-medium text-sm">Output #{idx}</p>
                    <Button 
                      size="sm" 
                      variant="destructive" 
                      onClick={() => removeOutput(idx)}
                      disabled={outputs.length === 1}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                  <Input 
                    placeholder="Value (satoshis)" 
                    type="number" 
                    value={out.value} 
                    onChange={(e) => updateOutput(idx, "value", parseInt(e.target.value))}
                  />
                  <Input 
                    placeholder="ScriptPubKey (hex)" 
                    value={out.scriptPubKey} 
                    onChange={(e) => updateOutput(idx, "scriptPubKey", e.target.value)}
                    className="font-mono text-xs"
                  />
                  {out.address && (
                    <Badge variant="outline">{out.address}</Badge>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Build & Preview */}
          <div className="flex gap-2">
            <Button onClick={buildTxHex} className="flex-1">Build Transaction</Button>
            <Button variant="outline" onClick={() => setShowPreview(!showPreview)}>
              <Eye className="w-4 h-4 mr-2" /> Preview
            </Button>
          </div>

          {/* Built Transaction */}
          {builtTxHex && (
            <Card>
              <CardHeader>
                <CardTitle>Built Transaction Hex</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Button size="sm" onClick={() => copyToClipboard(builtTxHex)}>
                  <Copy className="w-4 h-4 mr-2" /> Copy Hex
                </Button>
                <Textarea value={builtTxHex} readOnly rows={6} className="font-mono text-xs" />
              </CardContent>
            </Card>
          )}

          {/* Preview */}
          {showPreview && (
            <Card>
              <CardHeader>
                <CardTitle>Transaction Preview</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div>
                  <p className="font-medium">Structure:</p>
                  <code className="block bg-muted p-2 rounded mt-1">
                    Version: {version}<br/>
                    Inputs: {inputs.length}<br/>
                    Outputs: {outputs.length}<br/>
                    Size: {txSize} bytes<br/>
                    Locktime: {locktime}
                  </code>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
