"use client";

import {
  Radar,
  RadarChart as RechartsRadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
  Legend
} from 'recharts';

interface RadarData {
  subject: string;
  A: number;
  [key: string]: string | number; // For dynamic competitor data
}

export default function RadarChart({ mainTarget, competitors = [] }: { mainTarget: string, competitors?: any[] }) {
  // Mock data structure. In real app, this would come from the API
  const data: RadarData[] = [
    { subject: 'Crypto', A: 85 },
    { subject: 'Headers', A: 90 },
    { subject: 'DNS', A: 75 },
    { subject: 'Attack Surface', A: 80 },
    { subject: 'OSINT', A: 95 },
  ];

  // Colors for competitors
  const colors = ["#f59e0b", "#ef4444", "#3b82f6", "#8b5cf6", "#ec4899"];

  // Merge competitor data if present
  if (competitors && competitors.length > 0) {
    competitors.forEach((comp, idx) => {
      data[0][`C${idx}`] = 60 + Math.random() * 30;
      data[1][`C${idx}`] = 60 + Math.random() * 30;
      data[2][`C${idx}`] = 60 + Math.random() * 30;
      data[3][`C${idx}`] = 60 + Math.random() * 30;
      data[4][`C${idx}`] = 60 + Math.random() * 30;
    });
  }

  return (
    <div className="w-full h-80">
      <ResponsiveContainer width="100%" height="100%">
        <RechartsRadarChart cx="50%" cy="50%" outerRadius="80%" data={data}>
          <PolarGrid stroke="#e2e8f0" />
          <PolarAngleAxis dataKey="subject" tick={{ fill: '#64748b', fontSize: 12 }} />
          <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#94a3b8' }} />
          
          <Radar
            name={mainTarget || "Main Target"}
            dataKey="A"
            stroke="#22d3ee"
            fill="#22d3ee"
            fillOpacity={0.4}
          />
          
          {competitors && competitors.map((comp, idx) => (
            <Radar
              key={idx}
              name={comp.domain || `Competitor ${idx + 1}`}
              dataKey={`C${idx}`}
              stroke={colors[idx % colors.length]}
              fill={colors[idx % colors.length]}
              fillOpacity={0.2}
            />
          ))}
          
          <Tooltip 
            contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px' }}
            itemStyle={{ color: '#1e293b' }}
          />
          <Legend wrapperStyle={{ fontSize: '12px', color: '#475569' }} />
        </RechartsRadarChart>
      </ResponsiveContainer>
    </div>
  );
}
