import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Donut, DonutLegend, type DonutSlice } from './charts/Donut';

interface Props {
  componentCount: number;
  componentBreakdown: DonutSlice[];
  qualityIssues: DonutSlice[];
  qualityTotal: number;
  vulnerabilities: DonutSlice[];
  vulnTotal: number;
  licenses: DonutSlice[];
  licenseTotal: number;
}

export function OverviewDonuts(props: Props) {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <DonutCard title="Components" centerValue={props.componentCount} centerLabel="Components" data={props.componentBreakdown} />
      <DonutCard title="Quality Issues" centerValue={props.qualityTotal} centerLabel={props.qualityTotal === 1 ? 'Issue' : 'Issues'} data={props.qualityIssues} />
      <DonutCard title="Vulnerabilities" centerValue={props.vulnTotal} centerLabel={props.vulnTotal === 1 ? 'Vulnerability' : 'Vulnerabilities'} data={props.vulnerabilities} />
      <DonutCard title="Licenses" centerValue={props.licenseTotal} centerLabel={props.licenseTotal === 1 ? 'License' : 'Licenses'} data={props.licenses} />
    </div>
  );
}

function DonutCard({ title, centerValue, centerLabel, data }: { title: string; centerValue: number; centerLabel: string; data: DonutSlice[] }) {
  return (
    <Card>
      <CardHeader className="pb-2"><CardTitle className="text-center">{title}</CardTitle></CardHeader>
      <CardContent className="pt-2">
        <Donut data={data} centerValue={centerValue} centerLabel={centerLabel} />
        {data.length > 0 && data.some((d) => d.value > 0) && <DonutLegend data={data} />}
      </CardContent>
    </Card>
  );
}
