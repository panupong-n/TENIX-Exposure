import { ToggleGroup, ToggleGroupItem } from "tenix-exposure-ui";

export const Range = () => (<ToggleGroup defaultValue={["30"]}><ToggleGroupItem value="7">7d</ToggleGroupItem><ToggleGroupItem value="30">30d</ToggleGroupItem><ToggleGroupItem value="90">90d</ToggleGroupItem></ToggleGroup>);
