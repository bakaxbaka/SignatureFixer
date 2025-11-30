import React from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertTriangle } from 'lucide-react';
import { TransactionInput } from '@/lib/transaction-analyzer';

interface SignatureComparisonModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pubkey: string;
  signatures: (TransactionInput & { txid?: string })[];
}

export function SignatureComparisonModal({
  open,
  onOpenChange,
  pubkey,
  signatures,
}: SignatureComparisonModalProps) {
  // Find duplicate r values
  const rMap = new Map<string, number>();
  signatures.forEach((sig, idx) => {
    if (sig.signature?.r) {
      rMap.set(sig.signature.r, (rMap.get(sig.signature.r) || 0) + 1);
    }
  });

  const duplicateRs = Array.from(rMap.entries()).filter(([_, count]) => count > 1);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>📊 Signature Comparison</DialogTitle>
          <DialogDescription>
            Analysis of all signatures for pubkey {pubkey.substring(0, 16)}...
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Summary Stats */}
          <Card className="bg-blue-500/5 border-blue-500/20">
            <CardContent className="pt-4">
              <div className="grid grid-cols-4 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground mb-1">Total Signatures</p>
                  <p className="font-mono font-semibold text-lg">{signatures.length}</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">Unique r Values</p>
                  <p className="font-mono font-semibold text-lg">{rMap.size}</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">Duplicate r's</p>
                  <p className="font-mono font-semibold text-lg text-amber-600">{duplicateRs.length}</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">High-S Count</p>
                  <p className="font-mono font-semibold text-lg text-red-600">
                    {signatures.filter(s => s.signature?.isHighS).length}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Duplicate r Warning */}
          {duplicateRs.length > 0 && (
            <Alert className="bg-red-500/10 border-red-500/30">
              <AlertTriangle className="h-4 w-4 text-red-600" />
              <AlertDescription className="text-sm">
                ⚠ Found {duplicateRs.length} r value collision(s) - possible nonce reuse vulnerability!
              </AlertDescription>
            </Alert>
          )}

          {/* Signatures Table */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">All Signatures (r, s, z values)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="border-b font-semibold">
                    <tr>
                      <th className="text-left p-2">#</th>
                      <th className="text-left p-2">r Value</th>
                      <th className="text-left p-2">s Value</th>
                      <th className="text-left p-2">z-Hash</th>
                      <th className="text-left p-2">Flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {signatures.map((sig, idx) => (
                      <tr
                        key={idx}
                        className={`border-b hover:bg-muted/50 ${
                          duplicateRs.some(([r]) => r === sig.signature?.r) ? 'bg-red-500/5' : ''
                        }`}
                      >
                        <td className="p-2 font-semibold">{sig.index}</td>
                        <td className="p-2 font-mono text-xs">
                          {sig.signature?.r.substring(0, 8)}...
                          {duplicateRs.some(([r]) => r === sig.signature?.r) && (
                            <Badge className="ml-2 bg-red-600 text-xs">DUP</Badge>
                          )}
                        </td>
                        <td className="p-2 font-mono text-xs">{sig.signature?.s.substring(0, 8)}...</td>
                        <td className="p-2 font-mono text-xs">{sig.signature?.zHash.substring(0, 8)}...</td>
                        <td className="p-2">
                          <div className="flex flex-wrap gap-1">
                            {sig.signature?.isHighS && (
                              <Badge className="bg-amber-600 text-xs">High-S</Badge>
                            )}
                            {!sig.signature?.isCanonical && (
                              <Badge className="bg-red-600 text-xs">Non-can</Badge>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Duplicate r Details */}
          {duplicateRs.length > 0 && (
            <Card className="border-red-500/30 bg-red-500/5">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Nonce Reuse Detection</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {duplicateRs.map(([r, count], idx) => (
                  <div key={idx} className="text-xs p-2 border rounded">
                    <p className="font-semibold mb-1">r = {r.substring(0, 16)}... (used {count} times)</p>
                    <p className="text-muted-foreground">
                      Signatures: {signatures
                        .map((s, i) => s.signature?.r === r ? i : null)
                        .filter(i => i !== null)
                        .join(', ')}
                    </p>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Actions */}
          <div className="flex gap-2 pt-4 border-t">
            <Button onClick={() => onOpenChange(false)} className="ml-auto">
              Done
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
