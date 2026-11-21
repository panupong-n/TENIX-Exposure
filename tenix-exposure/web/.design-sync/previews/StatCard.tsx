import { StatCard, StatArt } from "tenix-exposure-ui";

const row = { display: "grid", gridTemplateColumns: "repeat(2, 240px)", gap: 12 } as const;
export const Overview = () => (
  <div style={row}>
    <StatCard title="Open findings" value="118,204" note="Across 2 CIDs" art={StatArt.layers} delta={{ value: -3.2, label: "vs last 30 days" }} />
    <StatCard title="Critical" value="37" note="4 on the CISA KEV list" alert art={StatArt.alert} delta={{ value: 5, label: "vs last 30 days" }} />
    <StatCard title="Devices" value="842" note="With the Falcon sensor" art={StatArt.device} />
    <StatCard title="Exploitable" value="219" note="Known exploited or high EPSS" art={StatArt.bolt} />
  </div>
);
