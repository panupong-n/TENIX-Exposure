import { Tabs, TabsContent, TabsList, TabsTrigger } from "tenix-exposure-ui";

export const Default = () => (
  <div style={{ maxWidth: 480 }}>
    <Tabs defaultValue="all">
      <TabsList>
        <TabsTrigger value="all">All sources</TabsTrigger>
        <TabsTrigger value="endpoint">Endpoints</TabsTrigger>
        <TabsTrigger value="external">External</TabsTrigger>
      </TabsList>
      <TabsContent value="all"><p style={{ fontSize: 14 }}>118,204 findings across 2 CIDs.</p></TabsContent>
      <TabsContent value="endpoint"><p style={{ fontSize: 14 }}>9,731 findings on devices with the Falcon sensor.</p></TabsContent>
      <TabsContent value="external"><p style={{ fontSize: 14 }}>108,473 findings on internet-facing assets.</p></TabsContent>
    </Tabs>
  </div>
);
