import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Code, Zap, Copy } from "lucide-react";

const transactionSchema = z.object({
  rawTransaction: z.string().min(1, "Raw transaction hex is required").regex(/^[0-9a-fA-F]+$/, "Invalid hex format"),
});

const txidSchema = z.object({
  txid: z.string().min(1, "Transaction ID is required").regex(/^[0-9a-fA-F]{64}$/, "Invalid transaction ID format"),
  networkType: z.enum(["mainnet", "testnet"]).default("mainnet"),
});

type TransactionForm = z.infer<typeof transactionSchema>;
type TxidForm = z.infer<typeof txidSchema>;

interface DecodedSignature {
  inputIndex: number;
  r: string;
  s: string;
  sighashType: number;
  publicKey: string;
  derEncoded: string;
}

interface DecodedTransaction {
  txid: string;
  version: number;
  inputs: Array<{
    txid: string;
    vout: number;
    script: string;
    sequence: number;
  }>;
  outputs: Array<{
    value: number;
    script: string;
    address?: string;
  }>;
  locktime: number;
  signatures: DecodedSignature[];
  vulnerabilityAnalysis?: any;
}

export function TransactionDecoder() {
  const [decodedResult, setDecodedResult] = useState<DecodedTransaction | null>(null);
  const [inputMode, setInputMode] = useState<'raw' | 'txid'>('raw');
  const [rawTxResult, setRawTxResult] = useState<string | null>(null);
  const { toast } = useToast();

  const form = useForm<TransactionForm>({
    resolver: zodResolver(transactionSchema),
  });

  const txidForm = useForm<TxidForm>({
    resolver: zodResolver(txidSchema),
    defaultValues: {
      networkType: "mainnet",
    },
  });

  const getRawTransaction = useMutation({
    mutationFn: async (data: TxidForm) => {
      const response = await apiRequest('POST', '/api/get-raw-transaction', data);
      return response.json();
    },
    onSuccess: (result) => {
      setRawTxResult(result.data.rawTransaction);
      // Auto-populate the raw transaction field
      form.setValue('rawTransaction', result.data.rawTransaction);
      toast({
        title: "Raw Transaction Retrieved",
        description: `Transaction ${result.data.txid} retrieved successfully`,
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to Get Raw Transaction",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const decodeTransaction = useMutation({
    mutationFn: async (data: TransactionForm) => {
      const response = await apiRequest('POST', '/api/decode-transaction', {
        rawTransaction: data.rawTransaction,
      });
      return response.json();
    },
    onSuccess: (result) => {
      setDecodedResult(result.data);
      toast({
        title: "Transaction Decoded",
        description: `Found ${result.data.signatures?.length || 0} signatures for analysis`,
      });
    },
    onError: (error) => {
      toast({
        title: "Decode Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: TransactionForm) => {
    decodeTransaction.mutate(data);
  };

  const onTxidSubmit = (data: TxidForm) => {
    getRawTransaction.mutate(data);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Text copied to clipboard",
    });
  };

  const getSighashTypeName = (type: number) => {
    const baseType = type & 0x1f;
    let name = "";
    
    switch (baseType) {
      case 0x01: name = "SIGHASH_ALL"; break;
      case 0x02: name = "SIGHASH_NONE"; break;
      case 0x03: name = "SIGHASH_SINGLE"; break;
      default: name = "UNKNOWN";
    }
    
    if (type & 0x80) {
      name += " | SIGHASH_ANYONECANPAY";
    }
    
    return `${name} (${type.toString(16).padStart(2, '0')})`;
  };

  const formatBTC = (satoshis: number) => {
    return (satoshis / 100000000).toFixed(8);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Code className="w-5 h-5 text-primary" />
          Advanced Transaction Decoder
        </CardTitle>
        <p className="text-sm text-muted-foreground">DER signature parsing and SIGHASH type analysis</p>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Input Mode Selector */}
        <div className="flex gap-2 p-1 bg-muted rounded-lg">
          <Button
            type="button"
            variant={inputMode === 'raw' ? 'default' : 'ghost'}
            size="sm"
            className="flex-1"
            onClick={() => setInputMode('raw')}
          >
            Raw Transaction
          </Button>
          <Button
            type="button"
            variant={inputMode === 'txid' ? 'default' : 'ghost'}
            size="sm"
            className="flex-1"
            onClick={() => setInputMode('txid')}
          >
            Transaction ID
          </Button>
        </div>

        {/* Transaction ID Form */}
        {inputMode === 'txid' && (
          <form onSubmit={txidForm.handleSubmit(onTxidSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="txid">Transaction ID</Label>
              <Textarea
                id="txid"
                placeholder="Enter 64-character transaction ID..."
                rows={2}
                className="font-mono text-sm resize-none"
                {...txidForm.register("txid")}
              />
              {txidForm.formState.errors.txid && (
                <p className="text-sm text-destructive">{txidForm.formState.errors.txid.message}</p>
              )}
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="networkType">Network</Label>
              <select
                id="networkType"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                {...txidForm.register("networkType")}
              >
                <option value="mainnet">Mainnet</option>
                <option value="testnet">Testnet</option>
              </select>
            </div>
            
            <Button
              type="submit"
              className="w-full"
              disabled={getRawTransaction.isPending}
            >
              <Zap className="w-4 h-4 mr-2" />
              {getRawTransaction.isPending ? 'Fetching...' : 'Get Raw Transaction'}
            </Button>
          </form>
        )}

        {/* Raw Transaction Form */}
        {inputMode === 'raw' && (
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="rawTransaction">Raw Transaction Hex</Label>
              <Textarea
                id="rawTransaction"
                placeholder="0100000001aabbccdd..."
                rows={4}
                className="font-mono text-sm resize-none"
                data-testid="textarea-raw-transaction"
                {...form.register("rawTransaction")}
              />
              {form.formState.errors.rawTransaction && (
                <p className="text-sm text-destructive">{form.formState.errors.rawTransaction.message}</p>
              )}
            </div>
            
            <Button
              type="submit"
              className="w-full"
              disabled={decodeTransaction.isPending}
              data-testid="button-decode-transaction"
            >
              <Zap className="w-4 h-4 mr-2" />
              {decodeTransaction.isPending ? 'Decoding...' : 'Decode & Analyze Signatures'}
            </Button>
          </form>
        )}

        {/* Raw Transaction Display */}
        {rawTxResult && (
          <div className="space-y-2">
            <Label>Retrieved Raw Transaction</Label>
            <div className="bg-muted/50 rounded-lg p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Raw Transaction Hex</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => copyToClipboard(rawTxResult)}
                >
                  <Copy className="w-3 h-3 mr-1" />
                  Copy
                </Button>
              </div>
              <p className="font-mono text-xs text-foreground break-all">
                {rawTxResult}
              </p>
            </div>
          </div>
        )}

        <Separator />

        {/* Decoded Results */}
        <div>
          <h3 className="text-md font-medium text-foreground mb-4">Signature Analysis Results</h3>
          
          {decodeTransaction.isPending ? (
            <div className="bg-muted/50 rounded-lg p-4">
              <div className="text-center py-8">
                <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-2" />
                <p className="text-muted-foreground text-sm">
                  Decoding transaction and extracting signatures...
                </p>
              </div>
            </div>
          ) : decodedResult ? (
            <div className="space-y-4">
              {/* Transaction Summary */}
              <div className="bg-muted/50 rounded-lg p-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Transaction ID:</span>
                    <p className="font-mono text-xs text-foreground break-all mt-1" data-testid="transaction-id">
                      {decodedResult.txid}
                    </p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Version:</span>
                    <span className="ml-2 font-mono text-foreground" data-testid="transaction-version">
                      {decodedResult.version}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Inputs:</span>
                    <span className="ml-2 font-mono text-foreground" data-testid="input-count">
                      {decodedResult.inputs.length}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Outputs:</span>
                    <span className="ml-2 font-mono text-foreground" data-testid="output-count">
                      {decodedResult.outputs.length}
                    </span>
                  </div>
                </div>
              </div>

              {/* Signatures */}
              {decodedResult.signatures && decodedResult.signatures.length > 0 ? (
                <div className="space-y-4">
                  <h4 className="font-medium text-foreground">Extracted Signatures</h4>
                  {decodedResult.signatures.map((signature, index) => (
                    <div key={index} className="border border-border rounded-lg p-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-muted-foreground">Input Index:</span>
                          <span className="ml-2 text-primary font-mono" data-testid={`signature-input-${index}`}>
                            {signature.inputIndex}
                          </span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">SIGHASH Type:</span>
                          <span className="ml-2 text-orange-500 font-mono text-xs" data-testid={`signature-sighash-${index}`}>
                            {getSighashTypeName(signature.sighashType)}
                          </span>
                        </div>
                        <div className="md:col-span-2">
                          <span className="text-muted-foreground">R Value:</span>
                          <p className="text-foreground font-mono text-xs mt-1 break-all" data-testid={`signature-r-${index}`}>
                            {signature.r}
                          </p>
                        </div>
                        <div className="md:col-span-2">
                          <span className="text-muted-foreground">S Value:</span>
                          <p className="text-foreground font-mono text-xs mt-1 break-all" data-testid={`signature-s-${index}`}>
                            {signature.s}
                          </p>
                        </div>
                      </div>
                      
                      {signature.publicKey && (
                        <div className="mt-3 pt-3 border-t border-border">
                          <span className="text-muted-foreground">Public Key:</span>
                          <p className="text-foreground font-mono text-xs mt-1 break-all" data-testid={`signature-pubkey-${index}`}>
                            {signature.publicKey}
                          </p>
                        </div>
                      )}
                      
                      <div className="mt-3 flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/20">
                          Valid DER
                        </Badge>
                        <Badge variant="outline" className="bg-blue-500/10 text-blue-500 border-blue-500/20">
                          Standard SIGHASH
                        </Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(signature.derEncoded)}
                          data-testid={`button-copy-der-${index}`}
                        >
                          <Copy className="w-3 h-3 mr-1" />
                          Copy DER
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-muted/50 rounded-lg p-4">
                  <div className="text-center py-4">
                    <p className="text-muted-foreground text-sm">No signatures found in transaction</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      This may be a coinbase transaction or contain non-standard scripts
                    </p>
                  </div>
                </div>
              )}

              {/* Vulnerability Analysis */}
              {decodedResult.vulnerabilityAnalysis && (
                <div className="space-y-4">
                  <h4 className="font-medium text-foreground">Vulnerability Analysis</h4>
                  <div className="bg-muted/50 rounded-lg p-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Risk Level:</span>
                        <span className="ml-2 font-medium" data-testid="vulnerability-risk-level">
                          {decodedResult.vulnerabilityAnalysis.summary?.riskLevel || 'Low'}
                        </span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Vulnerable Signatures:</span>
                        <span className="ml-2 font-mono text-destructive" data-testid="vulnerable-signatures">
                          {decodedResult.vulnerabilityAnalysis.summary?.vulnerableSignatures || 0}
                        </span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Pattern Matches:</span>
                        <span className="ml-2 font-mono text-orange-500" data-testid="pattern-matches">
                          {decodedResult.vulnerabilityAnalysis.patterns?.length || 0}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Transaction Inputs */}
              <div className="space-y-4">
                <h4 className="font-medium text-foreground">Transaction Inputs</h4>
                {decodedResult.inputs.map((input, index) => (
                  <div key={index} className="border border-border rounded-lg p-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                      <div>
                        <span className="text-muted-foreground">Previous TXID:</span>
                        <p className="font-mono text-xs text-foreground break-all mt-1" data-testid={`input-txid-${index}`}>
                          {input.txid}
                        </p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Output Index:</span>
                        <span className="ml-2 font-mono text-foreground" data-testid={`input-vout-${index}`}>
                          {input.vout}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Transaction Outputs */}
              <div className="space-y-4">
                <h4 className="font-medium text-foreground">Transaction Outputs</h4>
                {decodedResult.outputs.map((output, index) => (
                  <div key={index} className="border border-border rounded-lg p-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                      <div>
                        <span className="text-muted-foreground">Value:</span>
                        <span className="ml-2 font-mono text-foreground" data-testid={`output-value-${index}`}>
                          {formatBTC(output.value)} BTC
                        </span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Address:</span>
                        <span className="ml-2 font-mono text-foreground text-xs" data-testid={`output-address-${index}`}>
                          {output.address || 'N/A'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="bg-muted/50 rounded-lg p-4">
              <div className="text-center py-8">
                <Code className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-muted-foreground text-sm" data-testid="no-decode-message">
                  Enter raw transaction hex and click "Decode & Analyze Signatures" to begin analysis.
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  The decoder will extract all ECDSA signatures and analyze them for vulnerabilities.
                </p>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
