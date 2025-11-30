import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExternalLink, FlaskConical, Rocket, ScrollText } from "lucide-react";

interface Quest {
  id: string;
  title: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  category: string;
  summary: string;
  steps: string[];
  tags: string[];
  actionLabel: string;
}

const quests: Quest[] = [
  {
    id: "quest-forge-endpoint",
    title: "Forge a transaction via the API",
    difficulty: "intermediate",
    category: "automation",
    summary:
      "Call the /api/forge-signature endpoint with raw transaction hex and compare txids between the original and malleable versions.",
    steps: [
      "POST rawTxHex and optional malleabilityType (defaults to sighash_single)",
      "Validate the response includes malleableTransaction, malleableTxid, and originalTxid",
      "Record both txids to prove how malleability alters transaction IDs",
    ],
    tags: ["API", "forge-signature", "txid"],
    actionLabel: "Call /api/forge-signature",
  },
  {
    id: "quest-der-sweeps",
    title: "Run DER mutation sweeps",
    difficulty: "advanced",
    category: "der-malleability",
    summary:
      "Use derMutator services to generate multiple valid/invalid DER signatures for fuzzing and regression tests.",
    steps: [
      "Feed signature hex into mutateDER or generateAllMutations",
      "Collect high-S, zero-padding, bad length, and trailing-byte variants",
      "Use the set to validate library acceptance and rejection behaviors",
    ],
    tags: ["DER", "mutations", "fuzzing"],
    actionLabel: "Generate mutations",
  },
  {
    id: "quest-ui-hooks",
    title: "Script the UI mutation hooks",
    difficulty: "beginner",
    category: "e2e",
    summary:
      "Automate the vulnerability scanner or decoder flows that already post to /api/forge-signature and swap in the malleable transaction.",
    steps: [
      "Load a raw transaction in the scanner or decoder",
      "Trigger the forge action and wait for malleableTransaction + malleableTxid",
      "Assert the UI replaces the displayed tx with the forged version",
    ],
    tags: ["UI", "hooks", "e2e"],
    actionLabel: "Automate the flow",
  },
];

const difficultyStyles: Record<Quest["difficulty"], string> = {
  beginner: "bg-green-500/10 text-green-500 border-green-500/20",
  intermediate: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  advanced: "bg-red-500/10 text-red-500 border-red-500/20",
};

const categoryIcon: Record<string, JSX.Element> = {
  automation: <Rocket className="w-4 h-4 text-primary" />,
  "der-malleability": <FlaskConical className="w-4 h-4 text-orange-500" />,
  e2e: <ScrollText className="w-4 h-4 text-emerald-500" />,
};

export function AutomationQuests() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Rocket className="w-4 h-4 text-primary" />
          Automation Quests
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {quests.map((quest) => (
          <div
            key={quest.id}
            className="p-4 border border-border rounded-lg bg-muted/30 space-y-3"
            data-testid={`quest-${quest.id}`}
          >
            <div className="flex items-start gap-3">
              <div className="mt-1">
                {categoryIcon[quest.category] || <Rocket className="w-4 h-4 text-primary" />}
              </div>
              <div className="flex-1 space-y-2 min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-foreground truncate">{quest.title}</h3>
                  <Badge variant="outline" className={difficultyStyles[quest.difficulty]}>
                    {quest.difficulty}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed">{quest.summary}</p>
                <ul className="list-disc list-inside space-y-1 text-xs text-muted-foreground">
                  {quest.steps.map((step, index) => (
                    <li key={index}>{step}</li>
                  ))}
                </ul>
                <div className="flex flex-wrap gap-2">
                  {quest.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-[10px]">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="text-xs font-medium">
                {quest.actionLabel}
              </Button>
              <ExternalLink className="w-4 h-4 text-muted-foreground" />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
