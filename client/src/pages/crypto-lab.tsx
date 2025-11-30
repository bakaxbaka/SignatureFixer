import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Cve42461Panel } from "@/components/panels/Cve42461Panel";
import { WycheproofLab } from "@/components/panels/WycheproofLab";

export default function CryptoLab() {
  return (
    <div className="space-y-8 p-8">
      <div>
        <h1 className="text-4xl font-bold">Crypto Lab</h1>
        <p className="text-muted-foreground mt-2">
          Comprehensive vulnerability analysis & security testing
        </p>
      </div>

      <Tabs defaultValue="cve" className="w-full">
        <TabsList>
          <TabsTrigger value="cve" data-testid="tab-cve">
            CVE-2024-42461
          </TabsTrigger>
          <TabsTrigger value="wycheproof" data-testid="tab-wycheproof">
            Wycheproof Lab
          </TabsTrigger>
        </TabsList>

        <TabsContent value="cve" className="mt-8">
          <Cve42461Panel />
        </TabsContent>

        <TabsContent value="wycheproof" className="mt-8">
          <WycheproofLab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
