import { Pagination, PaginationContent, PaginationEllipsis, PaginationItem, PaginationLink, PaginationNext, PaginationPrevious } from "tenix-exposure-ui";

export const Pages = () => (
  <Pagination>
    <PaginationContent>
      <PaginationItem><PaginationPrevious /></PaginationItem>
      <PaginationItem><PaginationLink>1</PaginationLink></PaginationItem>
      <PaginationItem><PaginationLink isActive>2</PaginationLink></PaginationItem>
      <PaginationItem><PaginationLink>3</PaginationLink></PaginationItem>
      <PaginationItem><PaginationEllipsis /></PaginationItem>
      <PaginationItem><PaginationLink>48</PaginationLink></PaginationItem>
      <PaginationItem><PaginationNext /></PaginationItem>
    </PaginationContent>
  </Pagination>
);
