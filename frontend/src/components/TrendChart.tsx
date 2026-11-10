import { CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

export interface Series {
  key: string;
  label: string;
  color: string;
}

const axis = { stroke: '#64748b', fontSize: 11, tickLine: false, axisLine: false } as const;

export function TrendChart({
  data,
  series,
  height = 240,
  unit,
  threshold,
}: {
  data: Record<string, number | string>[];
  series: Series[];
  height?: number;
  unit?: string;
  threshold?: { value: number; label: string; color: string };
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
        <CartesianGrid stroke="#1e293b" vertical={false} />
        <XAxis dataKey="date" {...axis} minTickGap={28} tickFormatter={(d: string) => d.slice(5)} />
        <YAxis {...axis} width={48} tickFormatter={(v: number) => `${v}${unit ?? ''}`} />
        <Tooltip
          contentStyle={{ background: '#0c1220', border: '1px solid #22304f', borderRadius: 8, fontSize: 12 }}
          labelStyle={{ color: '#cbd5e1' }}
          formatter={(v: number, name: string) => [`${v}${unit ?? ''}`, name]}
        />
        <Legend iconType="plainline" wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} />
        {threshold && <ReferenceLine y={threshold.value} stroke={threshold.color} strokeDasharray="4 4" label={{ value: threshold.label, fill: threshold.color, fontSize: 10, position: 'insideTopRight' }} />}
        {series.map((s) => (
          <Line key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={s.color} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}
