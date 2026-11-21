import { InputGroup, InputGroupAddon, InputGroupText, InputGroupTextarea } from "tenix-exposure-ui";

export const Note = () => (<div style={{ maxWidth: 360 }}><InputGroup><InputGroupTextarea defaultValue="Rebooted after patch." /><InputGroupAddon align="block-end"><InputGroupText>21 / 280</InputGroupText></InputGroupAddon></InputGroup></div>);
