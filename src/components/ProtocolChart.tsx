import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, LabelList } from 'recharts';

interface ProtocolChartProps {
  data: Record<string, number>;
}

export const ProtocolChart: React.FC<ProtocolChartProps> = ({ data }) => {
  const chartData = Object.entries(data)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => Number(b.count) - Number(a.count))
    .slice(0, 10); // Top 10

  const colors = ['#0ea5e9', '#3b82f6', '#60a5fa', '#93c5fd', '#10b981', '#34d399', '#f59e0b', '#fbbf24', '#ef4444', '#f87171'];

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
          <XAxis type="number" stroke="#94a3b8" />
          <YAxis 
            dataKey="name" 
            type="category" 
            stroke="#94a3b8" 
            width={80} 
            tick={{fontSize: 12}}
          />
          <Tooltip 
            contentStyle={{ backgroundColor: '#1e293b', borderColor: '#475569', color: '#f1f5f9' }}
            cursor={{fill: '#334155', opacity: 0.4}}
            itemStyle={{ color: '#e2e8f0' }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
            ))}
            <LabelList 
              dataKey="count" 
              position="right" 
              fill="#f1f5f9" 
              fontSize={12}
              offset={4}
            />
        </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
