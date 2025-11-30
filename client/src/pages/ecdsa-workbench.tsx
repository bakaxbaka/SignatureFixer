import { useState, useEffect, useCallback } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Link } from "wouter";
import {
  AlertTriangle,
  Key,
  Copy,
  Calculator,
  Shield,
  CheckCircle,
  XCircle,
  ArrowLeft,
  Zap,
  Lock,
  Unlock,
  Hash,
  Binary,
  RefreshCw,
  Eye,
  EyeOff,
  Wallet,
  FileText,
} from "lucide-react";

import { BitcoinCrypto, getSecp256k1Params } from "@/lib/crypto";
import { MalleabilityDemo } from "@/components/malleability-demo";

const nonceReuseSchema = z.object({
  r: z.string().min(1, "R value is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  s1: z.string().min(1, "S1 value is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  s2: z.string().min(1, "S2 value is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  m1: z.string().min(1, "Message hash 1 is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  m2: z.string().min(1, "Message hash 2 is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
});

const knownNonceSchema = z.object({
  r: z.string().min(1, "R value is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  s: z.string().min(1, "S value is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  m: z.string().min(1, "Message hash is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  k: z.string().min(1, "Nonce (k) is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
});

const publicKeySchema = z.object({
  privateKey: z.string().min(1, "Private key is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
});

const signatureSchema = z.object({
  messageHash: z.string().min(1, "Message hash is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  privateKey: z.string().min(1, "Private key is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  nonce: z.string().min(1, "Nonce is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
});

const verifySchema = z.object({
  messageHash: z.string().min(1, "Message hash is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  pubKeyX: z.string().min(1, "Public key X is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  pubKeyY: z.string().min(1, "Public key Y is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  r: z.string().min(1, "R value is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  s: z.string().min(1, "S value is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
});

const pointValidateSchema = z.object({
  x: z.string().min(1, "X coordinate is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
  y: z.string().min(1, "Y coordinate is required").regex(/^[0-9a-fA-F]+$/, "Must be valid hex"),
});

const addressScanSchema = z.object({
  address: z.string().min(1, "Bitcoin address is required"),
});

type NonceReuseForm = z.infer<typeof nonceReuseSchema>;
type KnownNonceForm = z.infer<typeof knownNonceSchema>;
type PublicKeyForm = z.infer<typeof publicKeySchema>;
type SignatureForm = z.infer<typeof signatureSchema>;
type VerifyForm = z.infer<typeof verifySchema>;
type PointValidateForm = z.infer<typeof pointValidateSchema>;
type AddressScanForm = z.infer<typeof addressScanSchema>;

interface RecoveryResult {
  success: boolean;
  privateKey?: string;
  nonce?: string;
  publicKeyX?: string;
  publicKeyY?: string;
  compressedPubKey?: string;
  wif?: string;
  address?: string;
  error?: string;
  calculations?: {
    step: string;
    formula: string;
    value: string;
  }[];
}

interface VulnerabilityData {
  rValue: string;
  signatures: Array<{
    r: string;
    s: string;
    messageHash: string;
    txid?: string;
  }>;
  recoveredPrivateKey?: string;
  recoveredNonce?: string;
}

export default function ECDSAWorkbench() {
  const [activeTab, setActiveTab] = useState("auto-recovery");
  const [recoveryResult, setRecoveryResult] = useState<RecoveryResult | null>(null);
  const [publicKeyResult, setPublicKeyResult] = useState<any>(null);
  const [signResult, setSignResult] = useState<{ r: string; s: string } | null>(null);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [pointValid, setPointValid] = useState<boolean | null>(null);
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityData[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingStep, setProcessingStep] = useState("");
  const { toast } = useToast();

  const curveParams = getSecp256k1Params();

  const nonceReuseForm = useForm<NonceReuseForm>({
    resolver: zodResolver(nonceReuseSchema),
    defaultValues: { r: "", s1: "", s2: "", m1: "", m2: "" },
  });

  const knownNonceForm = useForm<KnownNonceForm>({
    resolver: zodResolver(knownNonceSchema),
    defaultValues: { r: "", s: "", m: "", k: "" },
  });

  const publicKeyForm = useForm<PublicKeyForm>({
    resolver: zodResolver(publicKeySchema),
    defaultValues: { privateKey: "" },
  });

  const signatureForm = useForm<SignatureForm>({
    resolver: zodResolver(signatureSchema),
    defaultValues: { messageHash: "", privateKey: "", nonce: "" },
  });

  const verifyForm = useForm<VerifyForm>({
    resolver: zodResolver(verifySchema),
    defaultValues: { messageHash: "", pubKeyX: "", pubKeyY: "", r: "", s: "" },
  });

  const pointValidateForm = useForm<PointValidateForm>({
    resolver: zodResolver(pointValidateSchema),
    defaultValues: { x: "", y: "" },
  });

  const addressScanForm = useForm<AddressScanForm>({
    resolver: zodResolver(addressScanSchema),
    defaultValues: { address: "" },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Value copied to clipboard",
    });
  };

  const scanForVulnerabilities = useMutation({
    mutationFn: async (address: string) => {
      const response = await apiRequest("POST", "/api/vulnerability-test", { address });
      return response.json();
    },
    onSuccess: async (result) => {
      if (result.data?.nonceReuse && result.data.nonceReuse.length > 0) {
        setVulnerabilities(result.data.nonceReuse);
        await processAllVulnerabilities(result.data.nonceReuse);
        toast({
          title: "Vulnerabilities Detected",
          description: `Found ${result.data.nonceReuse.length} nonce reuse instances. Auto-recovering private keys...`,
        });
      } else {
        setVulnerabilities([]);
        toast({
          title: "No Vulnerabilities Found",
          description: "No nonce reuse detected for this address",
        });
      }
    },
    onError: (error) => {
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const processAllVulnerabilities = async (vulns: VulnerabilityData[]) => {
    setIsProcessing(true);
    const results: RecoveryResult[] = [];

    for (let i = 0; i < vulns.length; i++) {
      const vuln = vulns[i];
      setProcessingStep(`Processing vulnerability ${i + 1} of ${vulns.length}...`);

      if (vuln.signatures.length >= 2) {
        const sig1 = vuln.signatures[0];
        const sig2 = vuln.signatures[1];

        try {
          const result = await performNonceReuseRecovery({
            r: sig1.r,
            s1: sig1.s,
            s2: sig2.s,
            m1: sig1.messageHash,
            m2: sig2.messageHash,
          });
          results.push(result);
        } catch (error) {
          console.error("Recovery failed:", error);
        }
      }
    }

    setIsProcessing(false);
    setProcessingStep("");

    if (results.length > 0 && results[0].success) {
      setRecoveryResult(results[0]);
      setActiveTab("recovery-details");
    }
  };

  const performNonceReuseRecovery = async (data: NonceReuseForm): Promise<RecoveryResult> => {
    const calculations: { step: string; formula: string; value: string }[] = [];

    try {
      const r = data.r.replace(/^0x/, "");
      const s1 = data.s1.replace(/^0x/, "");
      const s2 = data.s2.replace(/^0x/, "");
      const m1 = data.m1.replace(/^0x/, "");
      const m2 = data.m2.replace(/^0x/, "");

      calculations.push({
        step: "1. Parse Input Values",
        formula: "Convert hex strings to scalars in group order field",
        value: `r = 0x${r.slice(0, 16)}...\ns1 = 0x${s1.slice(0, 16)}...\ns2 = 0x${s2.slice(0, 16)}...`,
      });

      calculations.push({
        step: "2. Calculate Nonce (k)",
        formula: "k = (m₁ - m₂) × (s₁ - s₂)⁻¹ mod n",
        value: "Computing modular inverse and multiplication...",
      });

      const result = BitcoinCrypto.recoverFromNonceReuse({ r, s1, s2, m1, m2 });

      if (!result.success) {
        return {
          success: false,
          error: result.error || "Recovery failed",
          calculations,
        };
      }

      calculations.push({
        step: "3. Recovered Nonce",
        formula: "k = (m₁ - m₂) × (s₁ - s₂)⁻¹ mod n",
        value: `k = 0x${result.nonce}`,
      });

      calculations.push({
        step: "4. Calculate Private Key",
        formula: "x = (s × k - m) × r⁻¹ mod n",
        value: "Computing private key from nonce and signature...",
      });

      calculations.push({
        step: "5. Recovered Private Key",
        formula: "x = (s₁ × k - m₁) × r⁻¹ mod n",
        value: `x = 0x${result.privateKey}`,
      });

      const wif = await BitcoinCrypto.privateKeyToWIF(result.privateKey!, true, true);
      const address = await BitcoinCrypto.privateKeyToAddress(result.privateKey!, true, true);

      calculations.push({
        step: "6. Derive Public Key",
        formula: "Y = G × x (scalar multiplication on secp256k1)",
        value: `Compressed: ${result.compressedPubKey}`,
      });

      calculations.push({
        step: "7. Generate WIF & Address",
        formula: "WIF = Base58Check(0x80 + privateKey + 0x01 + checksum)",
        value: `WIF: ${wif}\nAddress: ${address}`,
      });

      return {
        success: true,
        privateKey: result.privateKey,
        nonce: result.nonce,
        publicKeyX: result.publicKeyX,
        publicKeyY: result.publicKeyY,
        compressedPubKey: result.compressedPubKey,
        wif,
        address,
        calculations,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
        calculations,
      };
    }
  };

  const onNonceReuseSubmit = async (data: NonceReuseForm) => {
    const result = await performNonceReuseRecovery(data);
    setRecoveryResult(result);
    if (result.success) {
      toast({
        title: "Private Key Recovered",
        description: "Successfully recovered private key from nonce reuse vulnerability",
      });
    } else {
      toast({
        title: "Recovery Failed",
        description: result.error,
        variant: "destructive",
      });
    }
  };

  const onKnownNonceSubmit = async (data: KnownNonceForm) => {
    const calculations: { step: string; formula: string; value: string }[] = [];

    try {
      const r = data.r.replace(/^0x/, "");
      const s = data.s.replace(/^0x/, "");
      const m = data.m.replace(/^0x/, "");
      const k = data.k.replace(/^0x/, "");

      calculations.push({
        step: "1. Parse Input Values",
        formula: "Convert hex to field elements",
        value: `r = 0x${r.slice(0, 16)}..., s = 0x${s.slice(0, 16)}..., k = 0x${k.slice(0, 16)}...`,
      });

      calculations.push({
        step: "2. Apply Known Nonce Formula",
        formula: "x = (s × k - m) × r⁻¹ mod n",
        value: "Computing private key...",
      });

      const result = BitcoinCrypto.recoverFromKnownNonce({ r, s, m, k });

      if (!result.success) {
        setRecoveryResult({ success: false, error: result.error, calculations });
        return;
      }

      calculations.push({
        step: "3. Recovered Private Key",
        formula: "x = (s × k - m) × r⁻¹ mod n",
        value: `x = 0x${result.privateKey}`,
      });

      const wif = await BitcoinCrypto.privateKeyToWIF(result.privateKey!, true, true);
      const address = await BitcoinCrypto.privateKeyToAddress(result.privateKey!, true, true);

      calculations.push({
        step: "4. Generate WIF & Address",
        formula: "Base58Check encoding",
        value: `WIF: ${wif}\nAddress: ${address}`,
      });

      setRecoveryResult({
        success: true,
        privateKey: result.privateKey,
        nonce: k,
        publicKeyX: result.publicKeyX,
        publicKeyY: result.publicKeyY,
        compressedPubKey: result.compressedPubKey,
        wif,
        address,
        calculations,
      });

      toast({
        title: "Private Key Recovered",
        description: "Successfully recovered from known nonce",
      });
    } catch (error) {
      setRecoveryResult({
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
        calculations,
      });
      toast({
        title: "Recovery Failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const onPublicKeySubmit = async (data: PublicKeyForm) => {
    try {
      const result = BitcoinCrypto.calculatePublicKey(data.privateKey);
      if (result) {
        const wif = await BitcoinCrypto.privateKeyToWIF(data.privateKey, true, true);
        const address = await BitcoinCrypto.privateKeyToAddress(data.privateKey, true, true);
        setPublicKeyResult({ ...result, wif, address });
        toast({ title: "Public Key Calculated" });
      } else {
        toast({ title: "Calculation Failed", variant: "destructive" });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const onSignSubmit = (data: SignatureForm) => {
    try {
      const result = BitcoinCrypto.signMessage(
        data.messageHash,
        data.privateKey,
        data.nonce
      );
      if (result) {
        setSignResult(result);
        toast({ title: "Message Signed" });
      } else {
        toast({ title: "Signing Failed", variant: "destructive" });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const onVerifySubmit = (data: VerifyForm) => {
    try {
      const result = BitcoinCrypto.verifySignature(
        data.messageHash,
        data.pubKeyX,
        data.pubKeyY,
        data.r,
        data.s
      );
      setVerifyResult(result);
      toast({
        title: result ? "Signature Valid" : "Signature Invalid",
        variant: result ? "default" : "destructive",
      });
    } catch (error) {
      setVerifyResult(false);
      toast({
        title: "Verification Error",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const onPointValidateSubmit = (data: PointValidateForm) => {
    try {
      const result = BitcoinCrypto.validatePoint(data.x, data.y);
      setPointValid(result);
      toast({
        title: result ? "Point is on Curve" : "Point is NOT on Curve",
        variant: result ? "default" : "destructive",
      });
    } catch (error) {
      setPointValid(false);
      toast({
        title: "Validation Error",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const onAddressScanSubmit = (data: AddressScanForm) => {
    scanForVulnerabilities.mutate(data.address);
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="bg-destructive/10 border-b border-destructive/20 px-4 py-3">
        <div className="max-w-7xl mx-auto flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0" />
          <p className="text-sm text-destructive font-medium">
            Educational Tool - Controlled Environment Only
          </p>
          <p className="text-sm text-muted-foreground flex-1">
            This ECDSA workbench demonstrates cryptographic vulnerabilities for cybersecurity education.
          </p>
        </div>
      </div>

      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Link href="/">
                <Button variant="ghost" size="sm" data-testid="button-back-home">
                  <ArrowLeft className="w-4 h-4 mr-2" />
                  Back
                </Button>
              </Link>
              <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
                <Calculator className="w-5 h-5 text-primary-foreground" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground">ECDSA Workbench</h1>
                <p className="text-sm text-muted-foreground">
                  secp256k1 Calculator & Private Key Recovery
                </p>
              </div>
            </div>
            <Badge variant="outline" className="bg-primary/10 text-primary border-primary/20">
              secp256k1
            </Badge>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid grid-cols-7 w-full">
            <TabsTrigger value="auto-recovery" data-testid="tab-auto-recovery">
              <Zap className="w-4 h-4 mr-2" />
              Auto Recovery
            </TabsTrigger>
            <TabsTrigger value="recovery-details" data-testid="tab-recovery-details">
              <FileText className="w-4 h-4 mr-2" />
              Details
            </TabsTrigger>
            <TabsTrigger value="manual-recovery" data-testid="tab-manual-recovery">
              <Key className="w-4 h-4 mr-2" />
              Manual
            </TabsTrigger>
            <TabsTrigger value="key-tools" data-testid="tab-key-tools">
              <Lock className="w-4 h-4 mr-2" />
              Key Tools
            </TabsTrigger>
            <TabsTrigger value="signature-lab" data-testid="tab-signature-lab">
              <Hash className="w-4 h-4 mr-2" />
              Sign/Verify
            </TabsTrigger>
            <TabsTrigger value="malleability" data-testid="tab-malleability">
              <Zap className="w-4 h-4 mr-2" />
              DER Malleable
            </TabsTrigger>
            <TabsTrigger value="curve-info" data-testid="tab-curve-info">
              <Binary className="w-4 h-4 mr-2" />
              Curve Info
            </TabsTrigger>
          </TabsList>

          <TabsContent value="auto-recovery" className="space-y-6">
            <Card className="border-primary/20 bg-primary/5">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="w-5 h-5 text-primary" />
                  Automatic Nonce Reuse Detection & Recovery
                </CardTitle>
                <CardDescription>
                  Enter a Bitcoin address to automatically scan for nonce reuse vulnerabilities
                  and recover private keys using ECDSA mathematics
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <form
                  onSubmit={addressScanForm.handleSubmit(onAddressScanSubmit)}
                  className="space-y-4"
                >
                  <div className="space-y-2">
                    <Label htmlFor="scan-address">Bitcoin Address</Label>
                    <Input
                      id="scan-address"
                      placeholder="Enter Bitcoin address to scan..."
                      {...addressScanForm.register("address")}
                      data-testid="input-scan-address"
                    />
                    {addressScanForm.formState.errors.address && (
                      <p className="text-sm text-destructive">
                        {addressScanForm.formState.errors.address.message}
                      </p>
                    )}
                  </div>
                  <Button
                    type="submit"
                    className="w-full"
                    disabled={scanForVulnerabilities.isPending || isProcessing}
                    data-testid="button-auto-scan"
                  >
                    {scanForVulnerabilities.isPending ? (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                        Scanning for Vulnerabilities...
                      </>
                    ) : isProcessing ? (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                        {processingStep}
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4 mr-2" />
                        Scan & Auto-Recover Private Keys
                      </>
                    )}
                  </Button>
                </form>

                {vulnerabilities.length > 0 && (
                  <div className="space-y-4 pt-4">
                    <Separator />
                    <h4 className="font-medium text-foreground flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-destructive" />
                      Detected Nonce Reuse Vulnerabilities
                    </h4>
                    {vulnerabilities.map((vuln, index) => (
                      <Card
                        key={index}
                        className="border-destructive/20 bg-destructive/5"
                        data-testid={`vulnerability-card-${index}`}
                      >
                        <CardContent className="p-4 space-y-3">
                          <div className="flex items-center justify-between">
                            <Badge variant="destructive">
                              Nonce Reuse #{index + 1}
                            </Badge>
                            <Badge variant="outline" className="bg-green-500/10 text-green-500">
                              Key Recoverable
                            </Badge>
                          </div>
                          <div className="space-y-2 text-sm">
                            <div>
                              <span className="text-muted-foreground">Shared R Value:</span>
                              <code className="ml-2 text-xs font-mono break-all">
                                {vuln.rValue.slice(0, 32)}...
                              </code>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Affected Signatures:</span>
                              <span className="ml-2 font-medium">{vuln.signatures.length}</span>
                            </div>
                          </div>
                          <Button
                            size="sm"
                            onClick={() => {
                              if (vuln.signatures.length >= 2) {
                                nonceReuseForm.setValue("r", vuln.signatures[0].r);
                                nonceReuseForm.setValue("s1", vuln.signatures[0].s);
                                nonceReuseForm.setValue("s2", vuln.signatures[1].s);
                                nonceReuseForm.setValue("m1", vuln.signatures[0].messageHash);
                                nonceReuseForm.setValue("m2", vuln.signatures[1].messageHash);
                                setActiveTab("manual-recovery");
                              }
                            }}
                            data-testid={`button-view-details-${index}`}
                          >
                            <Eye className="w-3 h-3 mr-1" />
                            View Full Details
                          </Button>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-muted/30">
              <CardHeader>
                <CardTitle className="text-sm">How Automatic Recovery Works</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground space-y-2">
                <p>
                  1. <strong>Scan:</strong> Fetches all transactions for the address
                </p>
                <p>
                  2. <strong>Analyze:</strong> Extracts ECDSA signatures and checks for duplicate R values
                </p>
                <p>
                  3. <strong>Detect:</strong> Identifies signature pairs sharing the same nonce
                </p>
                <p>
                  4. <strong>Recover:</strong> Applies mathematical formulas to extract the private key
                </p>
                <p>
                  5. <strong>Verify:</strong> Validates recovered key matches the public key on chain
                </p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="recovery-details" className="space-y-6">
            {recoveryResult ? (
              <div className="space-y-6">
                <Alert
                  variant={recoveryResult.success ? "default" : "destructive"}
                  className={
                    recoveryResult.success
                      ? "border-green-500/20 bg-green-500/5"
                      : ""
                  }
                >
                  {recoveryResult.success ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4" />
                  )}
                  <AlertTitle>
                    {recoveryResult.success
                      ? "Private Key Successfully Recovered"
                      : "Recovery Failed"}
                  </AlertTitle>
                  <AlertDescription>
                    {recoveryResult.success
                      ? "The private key was mathematically derived from the nonce reuse vulnerability"
                      : recoveryResult.error}
                  </AlertDescription>
                </Alert>

                {recoveryResult.success && (
                  <>
                    <Card className="border-destructive/30 bg-destructive/5">
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-destructive">
                          <Key className="w-5 h-5" />
                          Recovered Credentials
                        </CardTitle>
                        <CardDescription>
                          EDUCATIONAL DEMONSTRATION - These values are derived mathematically
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <Label>Private Key (Hex)</Label>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setShowPrivateKey(!showPrivateKey)}
                            >
                              {showPrivateKey ? (
                                <EyeOff className="w-4 h-4" />
                              ) : (
                                <Eye className="w-4 h-4" />
                              )}
                            </Button>
                          </div>
                          <div className="flex gap-2">
                            <code
                              className="flex-1 bg-muted rounded p-3 text-xs font-mono break-all"
                              data-testid="recovered-private-key"
                            >
                              {showPrivateKey
                                ? recoveryResult.privateKey
                                : "••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••"}
                            </code>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() =>
                                copyToClipboard(recoveryResult.privateKey!)
                              }
                            >
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label>WIF (Wallet Import Format)</Label>
                          <div className="flex gap-2">
                            <code className="flex-1 bg-muted rounded p-3 text-xs font-mono break-all">
                              {recoveryResult.wif}
                            </code>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => copyToClipboard(recoveryResult.wif!)}
                            >
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label>Bitcoin Address</Label>
                          <div className="flex gap-2">
                            <code className="flex-1 bg-muted rounded p-3 text-xs font-mono break-all">
                              {recoveryResult.address}
                            </code>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => copyToClipboard(recoveryResult.address!)}
                            >
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>

                        <Separator />

                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label>Recovered Nonce (k)</Label>
                            <code className="block bg-muted rounded p-2 text-xs font-mono break-all">
                              {recoveryResult.nonce?.slice(0, 32)}...
                            </code>
                          </div>
                          <div className="space-y-2">
                            <Label>Compressed Public Key</Label>
                            <code className="block bg-muted rounded p-2 text-xs font-mono break-all">
                              {recoveryResult.compressedPubKey?.slice(0, 32)}...
                            </code>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <Calculator className="w-5 h-5 text-primary" />
                          Mathematical Calculation Steps
                        </CardTitle>
                        <CardDescription>
                          Full derivation showing how the private key was recovered
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          {recoveryResult.calculations?.map((calc, index) => (
                            <div
                              key={index}
                              className="border rounded-lg p-4 bg-muted/30"
                              data-testid={`calculation-step-${index}`}
                            >
                              <div className="flex items-center gap-2 mb-2">
                                <Badge variant="outline">{calc.step}</Badge>
                              </div>
                              <p className="text-sm text-muted-foreground mb-2 font-mono">
                                {calc.formula}
                              </p>
                              <pre className="text-xs bg-background rounded p-2 overflow-x-auto whitespace-pre-wrap">
                                {calc.value}
                              </pre>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </>
                )}
              </div>
            ) : (
              <Card className="bg-muted/30">
                <CardContent className="py-12 text-center">
                  <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">
                    No recovery results yet. Use Auto Recovery or Manual Recovery to
                    analyze vulnerabilities.
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="manual-recovery" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="border-destructive/20">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Unlock className="w-5 h-5 text-destructive" />
                    Nonce Reuse Recovery
                  </CardTitle>
                  <CardDescription>
                    Recover private key when the same nonce (k) was used for two different
                    messages
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form
                    onSubmit={nonceReuseForm.handleSubmit(onNonceReuseSubmit)}
                    className="space-y-4"
                  >
                    <div className="space-y-2">
                      <Label>Shared R Value</Label>
                      <Input
                        placeholder="R value (hex)"
                        {...nonceReuseForm.register("r")}
                        data-testid="input-nonce-reuse-r"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>S₁ Value</Label>
                        <Input
                          placeholder="S1 (hex)"
                          {...nonceReuseForm.register("s1")}
                          data-testid="input-nonce-reuse-s1"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>S₂ Value</Label>
                        <Input
                          placeholder="S2 (hex)"
                          {...nonceReuseForm.register("s2")}
                          data-testid="input-nonce-reuse-s2"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Message Hash 1</Label>
                        <Input
                          placeholder="m1 (hex)"
                          {...nonceReuseForm.register("m1")}
                          data-testid="input-nonce-reuse-m1"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Message Hash 2</Label>
                        <Input
                          placeholder="m2 (hex)"
                          {...nonceReuseForm.register("m2")}
                          data-testid="input-nonce-reuse-m2"
                        />
                      </div>
                    </div>
                    <Button type="submit" className="w-full" data-testid="button-nonce-reuse-recover">
                      <Key className="w-4 h-4 mr-2" />
                      Recover Private Key
                    </Button>
                  </form>
                </CardContent>
              </Card>

              <Card className="border-orange-500/20">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Key className="w-5 h-5 text-orange-500" />
                    Known Nonce Recovery
                  </CardTitle>
                  <CardDescription>
                    Recover private key when the nonce (k) value is known
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form
                    onSubmit={knownNonceForm.handleSubmit(onKnownNonceSubmit)}
                    className="space-y-4"
                  >
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>R Value</Label>
                        <Input
                          placeholder="R (hex)"
                          {...knownNonceForm.register("r")}
                          data-testid="input-known-nonce-r"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>S Value</Label>
                        <Input
                          placeholder="S (hex)"
                          {...knownNonceForm.register("s")}
                          data-testid="input-known-nonce-s"
                        />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Message Hash</Label>
                      <Input
                        placeholder="Message hash (hex)"
                        {...knownNonceForm.register("m")}
                        data-testid="input-known-nonce-m"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Known Nonce (k)</Label>
                      <Input
                        placeholder="Nonce k (hex)"
                        {...knownNonceForm.register("k")}
                        data-testid="input-known-nonce-k"
                      />
                    </div>
                    <Button type="submit" className="w-full" data-testid="button-known-nonce-recover">
                      <Unlock className="w-4 h-4 mr-2" />
                      Recover from Known Nonce
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </div>

            <Card className="bg-muted/30">
              <CardHeader>
                <CardTitle className="text-sm">Mathematical Background</CardTitle>
              </CardHeader>
              <CardContent className="text-sm space-y-4 font-mono">
                <div>
                  <p className="text-muted-foreground mb-1">Nonce Reuse Formula:</p>
                  <p>k = (m₁ - m₂) × (s₁ - s₂)⁻¹ mod n</p>
                  <p>x = (s × k - m) × r⁻¹ mod n</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">Known Nonce Formula:</p>
                  <p>x = (s × k - m) × r⁻¹ mod n</p>
                </div>
                <p className="text-xs text-muted-foreground">
                  Where: x = private key, k = nonce, m = message hash, r,s = signature
                  components, n = curve order
                </p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="key-tools" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="w-5 h-5 text-primary" />
                    Public Key Calculator
                  </CardTitle>
                  <CardDescription>
                    Derive public key from private key using Y = G × x
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form
                    onSubmit={publicKeyForm.handleSubmit(onPublicKeySubmit)}
                    className="space-y-4"
                  >
                    <div className="space-y-2">
                      <Label>Private Key (Hex)</Label>
                      <Input
                        placeholder="Enter private key..."
                        {...publicKeyForm.register("privateKey")}
                        data-testid="input-private-key"
                      />
                    </div>
                    <Button type="submit" className="w-full" data-testid="button-calc-pubkey">
                      <Calculator className="w-4 h-4 mr-2" />
                      Calculate Public Key
                    </Button>
                  </form>

                  {publicKeyResult && (
                    <div className="mt-4 space-y-3">
                      <Separator />
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Public Key X:</Label>
                        <code className="block bg-muted rounded p-2 text-xs font-mono break-all">
                          {publicKeyResult.x}
                        </code>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Public Key Y:</Label>
                        <code className="block bg-muted rounded p-2 text-xs font-mono break-all">
                          {publicKeyResult.y}
                        </code>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Compressed:</Label>
                        <code className="block bg-muted rounded p-2 text-xs font-mono break-all">
                          {publicKeyResult.compressed}
                        </code>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">WIF:</Label>
                        <code className="block bg-muted rounded p-2 text-xs font-mono break-all">
                          {publicKeyResult.wif}
                        </code>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Address:</Label>
                        <code className="block bg-muted rounded p-2 text-xs font-mono break-all">
                          {publicKeyResult.address}
                        </code>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={publicKeyResult.isValid ? "default" : "destructive"}
                        >
                          {publicKeyResult.isValid ? "Valid Point" : "Invalid Point"}
                        </Badge>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="w-5 h-5 text-primary" />
                    Point Validator
                  </CardTitle>
                  <CardDescription>
                    Check if a point (x, y) lies on the secp256k1 curve: y² = x³ + 7
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form
                    onSubmit={pointValidateForm.handleSubmit(onPointValidateSubmit)}
                    className="space-y-4"
                  >
                    <div className="space-y-2">
                      <Label>X Coordinate (Hex)</Label>
                      <Input
                        placeholder="X coordinate..."
                        {...pointValidateForm.register("x")}
                        data-testid="input-point-x"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Y Coordinate (Hex)</Label>
                      <Input
                        placeholder="Y coordinate..."
                        {...pointValidateForm.register("y")}
                        data-testid="input-point-y"
                      />
                    </div>
                    <Button type="submit" className="w-full" data-testid="button-validate-point">
                      <CheckCircle className="w-4 h-4 mr-2" />
                      Validate Point
                    </Button>
                  </form>

                  {pointValid !== null && (
                    <div className="mt-4">
                      <Alert variant={pointValid ? "default" : "destructive"}>
                        {pointValid ? (
                          <CheckCircle className="h-4 w-4" />
                        ) : (
                          <XCircle className="h-4 w-4" />
                        )}
                        <AlertTitle>
                          {pointValid ? "Valid Point" : "Invalid Point"}
                        </AlertTitle>
                        <AlertDescription>
                          {pointValid
                            ? "The point satisfies y² ≡ x³ + 7 (mod p)"
                            : "The point does NOT satisfy the curve equation"}
                        </AlertDescription>
                      </Alert>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="signature-lab" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Hash className="w-5 h-5 text-primary" />
                    Sign Message
                  </CardTitle>
                  <CardDescription>
                    Create an ECDSA signature: s = (m + x × r) × k⁻¹ mod n
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form
                    onSubmit={signatureForm.handleSubmit(onSignSubmit)}
                    className="space-y-4"
                  >
                    <div className="space-y-2">
                      <Label>Message Hash (Hex)</Label>
                      <Input
                        placeholder="SHA256 hash of message..."
                        {...signatureForm.register("messageHash")}
                        data-testid="input-sign-message"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Private Key (Hex)</Label>
                      <Input
                        placeholder="Private key..."
                        {...signatureForm.register("privateKey")}
                        data-testid="input-sign-privkey"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Nonce k (Hex)</Label>
                      <Input
                        placeholder="Random nonce..."
                        {...signatureForm.register("nonce")}
                        data-testid="input-sign-nonce"
                      />
                    </div>
                    <Button type="submit" className="w-full" data-testid="button-sign">
                      <Hash className="w-4 h-4 mr-2" />
                      Sign Message
                    </Button>
                  </form>

                  {signResult && (
                    <div className="mt-4 space-y-3">
                      <Separator />
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">R Value:</Label>
                        <div className="flex gap-2">
                          <code className="flex-1 bg-muted rounded p-2 text-xs font-mono break-all">
                            {signResult.r}
                          </code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(signResult.r)}
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        </div>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">S Value:</Label>
                        <div className="flex gap-2">
                          <code className="flex-1 bg-muted rounded p-2 text-xs font-mono break-all">
                            {signResult.s}
                          </code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(signResult.s)}
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-primary" />
                    Verify Signature
                  </CardTitle>
                  <CardDescription>
                    Verify ECDSA signature using R = (G × m + Y × r) × s⁻¹
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form
                    onSubmit={verifyForm.handleSubmit(onVerifySubmit)}
                    className="space-y-4"
                  >
                    <div className="space-y-2">
                      <Label>Message Hash (Hex)</Label>
                      <Input
                        placeholder="SHA256 hash..."
                        {...verifyForm.register("messageHash")}
                        data-testid="input-verify-message"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Public Key X</Label>
                        <Input
                          placeholder="X coord..."
                          {...verifyForm.register("pubKeyX")}
                          data-testid="input-verify-pubx"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Public Key Y</Label>
                        <Input
                          placeholder="Y coord..."
                          {...verifyForm.register("pubKeyY")}
                          data-testid="input-verify-puby"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>R Value</Label>
                        <Input
                          placeholder="R..."
                          {...verifyForm.register("r")}
                          data-testid="input-verify-r"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>S Value</Label>
                        <Input
                          placeholder="S..."
                          {...verifyForm.register("s")}
                          data-testid="input-verify-s"
                        />
                      </div>
                    </div>
                    <Button type="submit" className="w-full" data-testid="button-verify">
                      <Shield className="w-4 h-4 mr-2" />
                      Verify Signature
                    </Button>
                  </form>

                  {verifyResult !== null && (
                    <div className="mt-4">
                      <Alert variant={verifyResult ? "default" : "destructive"}>
                        {verifyResult ? (
                          <CheckCircle className="h-4 w-4" />
                        ) : (
                          <XCircle className="h-4 w-4" />
                        )}
                        <AlertTitle>
                          {verifyResult ? "Valid Signature" : "Invalid Signature"}
                        </AlertTitle>
                        <AlertDescription>
                          {verifyResult
                            ? "The signature is mathematically valid for this message and public key"
                            : "The signature does NOT match the message and public key"}
                        </AlertDescription>
                      </Alert>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="curve-info" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Binary className="w-5 h-5 text-primary" />
                  secp256k1 Curve Parameters
                </CardTitle>
                <CardDescription>
                  The elliptic curve used by Bitcoin: y² = x³ + 7 over 𝔽ₚ
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Field Order (p)</Label>
                    <code className="block bg-muted rounded p-3 text-xs font-mono break-all">
                      0x{curveParams.fieldOrder}
                    </code>
                    <p className="text-xs text-muted-foreground">
                      = 2²⁵⁶ - 2³² - 977
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Curve Order (n)</Label>
                    <code className="block bg-muted rounded p-3 text-xs font-mono break-all">
                      0x{curveParams.curveOrder}
                    </code>
                    <p className="text-xs text-muted-foreground">
                      Number of points on the curve
                    </p>
                  </div>
                </div>

                <Separator />

                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">
                    Generator Point G (x coordinate)
                  </Label>
                  <code className="block bg-muted rounded p-3 text-xs font-mono break-all">
                    0x{curveParams.generatorX}
                  </code>
                </div>

                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">
                    Generator Point G (y coordinate)
                  </Label>
                  <code className="block bg-muted rounded p-3 text-xs font-mono break-all">
                    0x{curveParams.generatorY}
                  </code>
                </div>

                <Separator />

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Curve Parameter a</Label>
                    <code className="block bg-muted rounded p-3 text-xs font-mono">
                      {curveParams.a}
                    </code>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Curve Parameter b</Label>
                    <code className="block bg-muted rounded p-3 text-xs font-mono">
                      {curveParams.b}
                    </code>
                  </div>
                </div>

                <Alert>
                  <Binary className="h-4 w-4" />
                  <AlertTitle>Curve Equation</AlertTitle>
                  <AlertDescription className="font-mono">
                    y² ≡ x³ + 7 (mod p)
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>

            <Card className="bg-muted/30">
              <CardHeader>
                <CardTitle className="text-sm">ECDSA Formulas Reference</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm font-mono">
                <div>
                  <p className="text-muted-foreground mb-1">Key Generation:</p>
                  <p>Public Key: Y = G × x</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">Signing:</p>
                  <p>R = G × k</p>
                  <p>r = R.x mod n</p>
                  <p>s = (m + x × r) × k⁻¹ mod n</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">Verification:</p>
                  <p>R' = (G × m + Y × r) × s⁻¹</p>
                  <p>Valid if r ≡ R'.x (mod n)</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">Key Recovery (Nonce Reuse):</p>
                  <p>k = (m₁ - m₂) × (s₁ - s₂)⁻¹ mod n</p>
                  <p>x = (s × k - m) × r⁻¹ mod n</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="malleability" className="space-y-6">
            <MalleabilityDemo />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
