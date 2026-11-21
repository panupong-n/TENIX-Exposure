import { PaginationBar } from "tenix-exposure-ui";

export const Middle = () => (<div style={{ maxWidth: 640 }}><PaginationBar page={3} pageSize={25} total={1204} onPage={() => {}} /></div>);
export const FirstPage = () => (<div style={{ maxWidth: 640 }}><PaginationBar page={1} pageSize={25} total={18} onPage={() => {}} /></div>);
