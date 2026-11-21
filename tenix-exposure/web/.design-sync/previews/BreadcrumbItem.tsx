import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "tenix-exposure-ui";

export const Trail = () => (<Breadcrumb><BreadcrumbList><BreadcrumbItem><BreadcrumbLink href="/">Overview</BreadcrumbLink></BreadcrumbItem><BreadcrumbSeparator /><BreadcrumbItem><BreadcrumbLink href="/vulnerabilities">Vulnerabilities</BreadcrumbLink></BreadcrumbItem><BreadcrumbSeparator /><BreadcrumbItem><BreadcrumbPage>CVE-2024-3400</BreadcrumbPage></BreadcrumbItem></BreadcrumbList></Breadcrumb>);
