import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "tenix-exposure-ui";

export const Faq = () => (
  <div style={{ maxWidth: 480 }}>
    <Accordion defaultValue={["a"]}>
      <AccordionItem value="a"><AccordionTrigger>Why is a sync marked incomplete?</AccordionTrigger><AccordionContent>Falcon returned fewer findings than it reported, or the 400,000 finding ceiling was reached. The previous complete data stays on screen.</AccordionContent></AccordionItem>
      <AccordionItem value="b"><AccordionTrigger>Who can see the CID?</AccordionTrigger><AccordionContent>Only Super Admins. Customers never see it.</AccordionContent></AccordionItem>
    </Accordion>
  </div>
);
