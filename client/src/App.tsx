import React from "react";
import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Home from "@/pages/home";
import ECDSAWorkbench from "@/pages/ecdsa-workbench";
import BlockScanner from "@/pages/block-scanner";
import NotFound from "@/pages/not-found";

const SignatureTools = React.lazy(() => import("@/pages/signature-tools"));
const RawTxBuilder = React.lazy(() => import("@/pages/raw-tx-builder"));
const VulnerabilityHistory = React.lazy(() => import("@/pages/vulnerability-history"));

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/ecdsa-workbench" component={ECDSAWorkbench} />
      <Route path="/block-scanner" component={BlockScanner} />
      <Route path="/signature-tools">
        {() => (
          <React.Suspense fallback={<div className="p-8 text-center">Loading...</div>}>
            <SignatureTools />
          </React.Suspense>
        )}
      </Route>
      <Route path="/raw-tx-builder">
        {() => (
          <React.Suspense fallback={<div className="p-8 text-center">Loading...</div>}>
            <RawTxBuilder />
          </React.Suspense>
        )}
      </Route>
      <Route path="/vulnerability-history">
        {() => (
          <React.Suspense fallback={<div className="p-8 text-center">Loading...</div>}>
            <VulnerabilityHistory />
          </React.Suspense>
        )}
      </Route>
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="dark min-h-screen bg-background text-foreground">
          <Toaster />
          <Router />
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
