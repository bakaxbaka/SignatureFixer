/**
 * Signature Analyzer
 * Extracts signatures and pubkeys from scriptSig and witness
 */

export interface SignatureInfo {
  derHex: string;
  pubkeyHex?: string;
  sighashType: number;
  prevOutputScriptHex?: string;
  prevOutputValueSats?: number;
}

export function extractInputSignature(input: any): SignatureInfo | null {
  try {
    // Try witness first (SegWit)
    if (input.witness && input.witness.length >= 2) {
      const signature = input.witness[0];
      const pubkey = input.witness[1];
      
      if (signature && pubkey) {
        const sighashType = Buffer.from(signature, "hex")[Buffer.from(signature, "hex").length - 1];
        return {
          derHex: signature,
          pubkeyHex: pubkey,
          sighashType: sighashType || 0x01,
        };
      }
    }

    // Try scriptSig (Legacy)
    if (input.scriptSig) {
      const script = Buffer.from(input.scriptSig, "hex");
      
      // Parse scriptSig for signature + pubkey
      let offset = 0;
      
      // First push: signature
      if (offset < script.length) {
        const len1 = script[offset];
        offset++;
        
        if (offset + len1 <= script.length) {
          const signature = script.slice(offset, offset + len1).toString("hex");
          offset += len1;
          
          const sighashType = script[offset - 1];
          
          // Second push: pubkey
          if (offset < script.length) {
            const len2 = script[offset];
            offset++;
            
            if (offset + len2 <= script.length) {
              const pubkey = script.slice(offset, offset + len2).toString("hex");
              
              return {
                derHex: signature,
                pubkeyHex: pubkey,
                sighashType: sighashType || 0x01,
              };
            }
          }
        }
      }
    }

    return null;
  } catch (e) {
    return null;
  }
}
