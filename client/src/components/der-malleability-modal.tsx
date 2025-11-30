import React, { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Copy, Download } from 'lucide-react';
import { generateMalleableVariants, isCanonical } from '@/lib/der-malleability';
import { useToast } from '@/hooks/use-toast';

interface DERMalleabilityModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  originalDER: string;
  sighashByte?: number;
}

export function DERMalleabilityModal({
  open,
  onOpenChange,
  originalDER,
  sighashByte = 0x01,
}: DERMalleabilityModalProps) {
  const { toast } = useToast();
  const [selectedVariant, setSelectedVariant] = useState(0);

  const variants = generateMalleableVariants(originalDER);
  const current = variants[selectedVariant];

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ description: 'Copied to clipboard' });
  };

  const downloadJSON = () => {
    const data = {
      original: originalDER,
      sighashByte,
      canonical: isCanonical(originalDER),
      variants: variants.map(v => ({
        name: v.name,
        description: v.description,
        der: v.der,
        isCanonical: isCanonical(v.der),
        category: v.category,
      })),
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'der-variants.json';
    a.click();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>🔄 DER Malleability Playground</DialogTitle>
          <DialogDescription>
            Explore non-canonical DER variants for CVE-class vulnerability testing
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Variant Selector */}
          <div>
            <p className="text-sm font-semibold mb-2">Variants ({variants.length})</p>
            <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto">
              {variants.map((v, idx) => (
                <button
                  key={idx}
                  onClick={() => setSelectedVariant(idx)}
                  className={`p-2 rounded border text-left text-sm transition-colors ${
                    selectedVariant === idx
                      ? 'bg-blue-600 border-blue-600 text-white'
                      : 'bg-muted border-border hover:bg-muted/80'
                  }`}
                >
                  <div className="font-semibold">{v.name}</div>
                  <div className="text-xs opacity-80">{v.category}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Current Variant Details */}
          {current && (
            <Card className="border-purple-500/30 bg-purple-500/5">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">{current.name}</CardTitle>
                  <div className="flex gap-2">
                    <Badge
                      className={
                        isCanonical(current.der)
                          ? 'bg-green-600'
                          : 'bg-red-600'
                      }
                    >
                      {isCanonical(current.der) ? '✓ Canonical' : '⚠ Non-canonical'}
                    </Badge>
                    <Badge variant="outline">{current.category}</Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">{current.description}</p>

                {/* DER Display */}
                <div className="space-y-2">
                  <p className="text-xs font-semibold">DER Signature</p>
                  <div className="bg-muted rounded p-3 flex items-center justify-between">
                    <code className="font-mono text-xs break-all">{current.der}</code>
                    <button
                      onClick={() => copyToClipboard(current.der)}
                      className="p-1 hover:bg-background rounded ml-2 flex-shrink-0"
                      title="Copy"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Size Comparison */}
                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div className="border rounded p-2">
                    <p className="text-muted-foreground mb-1">Bytes</p>
                    <p className="font-mono font-semibold">{current.der.length / 2}</p>
                  </div>
                  <div className="border rounded p-2">
                    <p className="text-muted-foreground mb-1">vs Original</p>
                    <p className="font-mono font-semibold">
                      {current.der.length === originalDER.length
                        ? '='
                        : current.der.length > originalDER.length
                          ? `+${current.der.length / 2 - originalDER.length / 2}`
                          : `-${originalDER.length / 2 - current.der.length / 2}`}
                    </p>
                  </div>
                </div>

                {/* Variant Info */}
                <div className="bg-muted/50 rounded p-2 text-xs">
                  <p className="text-muted-foreground">
                    <strong>Test Purpose:</strong> This variant tests if your target library/wallet accepts
                    {current.category === 'high-s' ? ' non-standard S value encoding' : ''}
                    {current.category === 'extra-zeros' ? ' extra leading zeros' : ''}
                    {current.category === 'seq-length' ? ' alternative length encoding' : ''}
                    {current.category === 'trailing' ? ' trailing data' : ''}
                    {current.category === 'canonical' ? ' canonical encoding (baseline)' : ''}.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {/* All Variants Table */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">All Variants Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="border-b font-semibold">
                    <tr>
                      <th className="text-left p-2">Name</th>
                      <th className="text-left p-2">Category</th>
                      <th className="text-left p-2">Canonical</th>
                      <th className="text-left p-2">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {variants.map((v, idx) => (
                      <tr
                        key={idx}
                        className={`border-b hover:bg-muted/50 cursor-pointer ${
                          selectedVariant === idx ? 'bg-muted/80' : ''
                        }`}
                        onClick={() => setSelectedVariant(idx)}
                      >
                        <td className="p-2 font-semibold">{v.name}</td>
                        <td className="p-2">{v.category}</td>
                        <td className="p-2">
                          <Badge
                            className="text-xs"
                            variant={isCanonical(v.der) ? 'default' : 'destructive'}
                          >
                            {isCanonical(v.der) ? '✓' : '✗'}
                          </Badge>
                        </td>
                        <td className="p-2 font-mono">{v.der.length / 2}B</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Actions */}
          <div className="flex gap-2 pt-4 border-t">
            <Button
              onClick={downloadJSON}
              variant="outline"
              className="gap-2"
            >
              <Download className="w-4 h-4" />
              Export JSON
            </Button>
            <Button
              onClick={() => copyToClipboard(variants.map(v => v.der).join('\n'))}
              variant="outline"
            >
              Copy All DERs
            </Button>
            <Button
              onClick={() => onOpenChange(false)}
              className="ml-auto"
            >
              Done
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
