import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { ScanSearch, Search, Copy, Shield, Coins, SearchX } from "lucide-react";
import { isValidBitcoinAddress } from "@/lib/bitcoin-utils";

const addressSchema = z.object({
  address: z.string().min(26).max(62).refine((val) => isValidBitcoinAddress(val), {
    message: "Invalid Bitcoin address format",
  }),
  networkType: z.enum(["mainnet", "testnet"]).default("mainnet"),
  batchMode: z.boolean().default(false),
});

type AddressForm = z.infer<typeof addressSchema>;

interface UTXOResult {
  utxos: Array<{
    txid: string;
    vout: number;
    value: number;
    confirmations: number;
    script: string;
  }>;
  totalValue: number;
  totalUTXOs: number;
  source: string;
}

export function AddressAnalyzer() {
  const [analysisResult, setAnalysisResult] = useState<UTXOResult | null>(null);
  const [currentAddress, setCurrentAddress] = useState<string>("");
  const { toast } = useToast();

  const form = useForm<AddressForm>({
    resolver: zodResolver(addressSchema),
    defaultValues: {
      networkType: "mainnet",
      batchMode: false,
    },
  });

  const analyzeUTXOs = useMutation({
    mutationFn: async (data: AddressForm) => {
      const response = await apiRequest('POST', '/api/utxos', {
        address: data.address,
        networkType: data.networkType,
      });
      return response.json();
    },
    onSuccess: (result) => {
      setAnalysisResult(result.data);
      setCurrentAddress(form.getValues('address'));
      toast({
        title: "Analysis Complete",
        description: `Found ${result.data.totalUTXOs} UTXOs with total value of ${(result.data.totalValue / 100000000).toFixed(8)} BTC`,
      });
    },
    onError: (error) => {
      toast({
        title: "Analysis Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: AddressForm) => {
    analyzeUTXOs.mutate(data);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Text copied to clipboard",
    });
  };

  const formatBTC = (satoshis: number) => {
    return (satoshis / 100000000).toFixed(8);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ScanSearch className="w-5 h-5 text-primary" />
          Bitcoin Address Analysis
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-6">
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          {/* Network Type Selector */}
          <div className="flex items-center gap-4">
            <span className="text-sm text-muted-foreground">Network Type:</span>
            <div className="flex bg-muted rounded-lg p-1">
              <Button
                type="button"
                size="sm"
                variant={form.watch('networkType') === 'mainnet' ? 'default' : 'ghost'}
                onClick={() => form.setValue('networkType', 'mainnet')}
                data-testid="button-mainnet"
              >
                Mainnet
              </Button>
              <Button
                type="button"
                size="sm"
                variant={form.watch('networkType') === 'testnet' ? 'default' : 'ghost'}
                onClick={() => form.setValue('networkType', 'testnet')}
                data-testid="button-testnet"
              >
                Testnet
              </Button>
            </div>
          </div>

          {/* Address Input */}
          <div className="space-y-2">
            <Label htmlFor="address">Bitcoin Address</Label>
            <div className="relative">
              <Input
                id="address"
                placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
                className="font-mono pr-10"
                data-testid="input-bitcoin-address"
                {...form.register("address")}
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="absolute right-2 top-1/2 -translate-y-1/2 h-6 w-6 p-0"
                onClick={() => copyToClipboard(form.getValues('address'))}
                data-testid="button-copy-address"
              >
                <Copy className="w-4 h-4" />
              </Button>
            </div>
            {form.formState.errors.address && (
              <p className="text-sm text-destructive">{form.formState.errors.address.message}</p>
            )}
          </div>
          
          {/* Batch Mode Toggle */}
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="batchMode"
                checked={form.watch('batchMode')}
                onCheckedChange={(checked) => form.setValue('batchMode', !!checked)}
                data-testid="checkbox-batch-mode"
              />
              <Label htmlFor="batchMode" className="text-sm text-muted-foreground">
                Enable batch analysis mode
              </Label>
            </div>
            <Button type="button" variant="link" size="sm" data-testid="button-import-addresses">
              Import address list
            </Button>
          </div>

          <div className="flex gap-2">
            <Button
              type="submit"
              className="flex-1"
              disabled={analyzeUTXOs.isPending}
              data-testid="button-analyze-utxos"
            >
              <Search className="w-4 h-4 mr-2" />
              {analyzeUTXOs.isPending ? 'Analyzing...' : 'Analyze UTXOs'}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="icon"
              data-testid="button-vulnerability-scan"
            >
              <Shield className="w-4 h-4" />
            </Button>
          </div>
        </form>

        <Separator />

        {/* UTXO Results */}
        <div>
          <h3 className="text-md font-medium text-foreground mb-4 flex items-center gap-2">
            <Coins className="w-4 h-4 text-primary" />
            Unspent Transaction Outputs (UTXOs)
          </h3>
          
          {analyzeUTXOs.isPending ? (
            <div className="bg-muted/50 rounded-lg p-4">
              <div className="text-center py-8">
                <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-2" />
                <p className="text-muted-foreground text-sm">
                  Analyzing address across multiple blockchain APIs...
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  Querying Blockchain.com, Blockstream Esplora, and SoChain APIs
                </p>
              </div>
            </div>
          ) : analysisResult ? (
            <div className="space-y-4">
              {/* Summary */}
              <div className="bg-muted/50 rounded-lg p-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Total UTXOs:</span>
                    <span className="ml-2 font-mono text-foreground" data-testid="total-utxos">
                      {analysisResult.totalUTXOs}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Total Value:</span>
                    <span className="ml-2 font-mono text-foreground" data-testid="total-value">
                      {formatBTC(analysisResult.totalValue)} BTC
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Source:</span>
                    <span className="ml-2 text-primary" data-testid="data-source">
                      {analysisResult.source}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Address:</span>
                    <span className="ml-2 font-mono text-xs text-foreground break-all" data-testid="current-address">
                      {currentAddress}
                    </span>
                  </div>
                </div>
              </div>

              {/* UTXO List */}
              {analysisResult.utxos.length > 0 ? (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {analysisResult.utxos.map((utxo, index) => (
                    <div key={`${utxo.txid}-${utxo.vout}`} className="border border-border rounded-lg p-3">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
                        <div>
                          <span className="text-muted-foreground">TXID:</span>
                          <p className="font-mono text-xs text-foreground break-all mt-1" data-testid={`utxo-txid-${index}`}>
                            {utxo.txid}
                          </p>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Output:</span>
                          <span className="ml-2 font-mono text-foreground" data-testid={`utxo-vout-${index}`}>
                            {utxo.vout}
                          </span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Value:</span>
                          <span className="ml-2 font-mono text-foreground" data-testid={`utxo-value-${index}`}>
                            {formatBTC(utxo.value)} BTC
                          </span>
                        </div>
                      </div>
                      <div className="mt-2 flex items-center gap-2">
                        <Badge variant="outline" data-testid={`utxo-confirmations-${index}`}>
                          {utxo.confirmations} confirmations
                        </Badge>
                        {utxo.script && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(utxo.script)}
                            data-testid={`button-copy-script-${index}`}
                          >
                            <Copy className="w-3 h-3 mr-1" />
                            Script
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-muted/50 rounded-lg p-4">
                  <div className="text-center py-4">
                    <SearchX className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-muted-foreground text-sm">No UTXOs found for this address</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      The address has no unspent transaction outputs
                    </p>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-muted/50 rounded-lg p-4">
              <div className="text-center py-8">
                <SearchX className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-muted-foreground text-sm" data-testid="no-analysis-message">
                  No UTXOs found. Enter a Bitcoin address and click "Analyze UTXOs" to begin analysis.
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  The system will query Blockchain.com, Blockstream Esplora, and SoChain APIs simultaneously.
                </p>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
