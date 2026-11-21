import { SearchInput } from "tenix-exposure-ui";

export const Default = () => (<div style={{ maxWidth: 320 }}><SearchInput value="" onChange={() => {}} placeholder="Search CVE, device or software" /></div>);
export const WithValue = () => (<div style={{ maxWidth: 320 }}><SearchInput value="CVE-2024-3400" onChange={() => {}} placeholder="Search" /></div>);
