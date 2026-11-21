import { Table, TableBody, TableCell, TableHeader, TableRow, SeverityBadge } from "tenix-exposure-ui";

// Table is an unstyled primitive: screens pass the classes below (same as the Overview and Vulnerabilities pages).
const head = "py-1.5 pe-3 text-start text-xs font-medium text-gray-500 dark:text-gray-400";
const headEnd = "py-1.5 text-end text-xs font-medium text-gray-500 dark:text-gray-400";
const rows = [
  ["CVE-2024-3400", "CRITICAL", "PAN-OS", 12],
  ["CVE-2023-4863", "HIGH", "Google Chrome", 87],
  ["CVE-2024-21412", "MEDIUM", "Windows 11", 41],
  ["CVE-2023-38545", "LOW", "curl", 6],
] as const;

export const Findings = () => (
  <div style={{ maxWidth: 560 }}>
    <Table>
      <TableHeader className="border-y border-gray-100 dark:border-gray-800">
        <TableRow>
          <TableCell isHeader className={head}>CVE</TableCell>
          <TableCell isHeader className={head}>Severity</TableCell>
          <TableCell isHeader className={head}>Software</TableCell>
          <TableCell isHeader className={headEnd}>Devices</TableCell>
        </TableRow>
      </TableHeader>
      <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
        {rows.map((r) => (
          <TableRow key={r[0]} className="cursor-pointer transition-colors hover:bg-gray-50">
            <TableCell className="py-1.5 pe-3 text-sm font-medium text-gray-800">{r[0]}</TableCell>
            <TableCell className="py-1.5 pe-3"><SeverityBadge severity={r[1]} /></TableCell>
            <TableCell className="py-1.5 pe-3 text-sm text-gray-500">{r[2]}</TableCell>
            <TableCell className="py-1.5 text-end text-sm text-gray-500 tabular-nums">{r[3]}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  </div>
);
