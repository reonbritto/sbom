'use client';

import { Cell, Pie, PieChart, ResponsiveContainer } from 'recharts';

export interface DonutSlice {
  label: string;
  value: number;
  color: string;
}

interface Props {
  data: DonutSlice[];
  centerValue: string | number;
  centerLabel?: string;
  size?: number;
}

export function Donut({ data, centerValue, centerLabel, size = 180 }: Props) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const chartData = total === 0
    ? [{ label: 'empty', value: 1, color: 'hsl(var(--muted))' }]
    : data;

  return (
    <div className="relative" style={{ height: size, width: '100%' }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            dataKey="value"
            nameKey="label"
            innerRadius="68%"
            outerRadius="100%"
            paddingAngle={chartData.length > 1 ? 2 : 0}
            startAngle={90}
            endAngle={-270}
            stroke="none"
          >
            {chartData.map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="text-3xl font-bold leading-none">{centerValue}</div>
        {centerLabel && <div className="text-xs text-muted-foreground mt-1">{centerLabel}</div>}
      </div>
    </div>
  );
}

export function DonutLegend({ data }: { data: DonutSlice[] }) {
  return (
    <div className="mt-3 flex flex-col gap-1.5 text-xs">
      {data.map((d) => (
        <div key={d.label} className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <span className="h-2.5 w-2.5 rounded-sm shrink-0" style={{ background: d.color }} />
            <span className="text-muted-foreground truncate">{d.label}</span>
          </div>
          <span className="font-semibold tabular-nums">{d.value}</span>
        </div>
      ))}
    </div>
  );
}
