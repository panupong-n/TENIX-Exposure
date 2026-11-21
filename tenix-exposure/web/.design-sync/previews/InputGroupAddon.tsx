import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput, InputGroupText } from "tenix-exposure-ui";

export const Search = () => (<div style={{ maxWidth: 360, display: "flex", flexDirection: "column", gap: 12 }}><InputGroup><InputGroupAddon><InputGroupText>https://</InputGroupText></InputGroupAddon><InputGroupInput placeholder="exposure.example.com" /></InputGroup><InputGroup><InputGroupInput defaultValue="CVE-2024-3400" /><InputGroupAddon align="inline-end"><InputGroupButton>Search</InputGroupButton></InputGroupAddon></InputGroup></div>);
