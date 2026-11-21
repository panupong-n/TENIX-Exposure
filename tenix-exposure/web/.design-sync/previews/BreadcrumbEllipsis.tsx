import { Breadcrumb, BreadcrumbEllipsis, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "tenix-exposure-ui";

export const Collapsed = () => (<Breadcrumb><BreadcrumbList><BreadcrumbItem><BreadcrumbLink href="/">Overview</BreadcrumbLink></BreadcrumbItem><BreadcrumbSeparator /><BreadcrumbItem><BreadcrumbEllipsis /></BreadcrumbItem><BreadcrumbSeparator /><BreadcrumbItem><BreadcrumbPage>Alpha Corp</BreadcrumbPage></BreadcrumbItem></BreadcrumbList></Breadcrumb>);
