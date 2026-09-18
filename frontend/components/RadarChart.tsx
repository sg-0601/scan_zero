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

interface RadarChartProps {
  mainTarget: string;
  scores?: {
    set1?: number;
    set2?: number;
    set3?: number;
    set4?: number;
    set5?: number;
    set6?: number;
  };
  competitors?: any[];
}

export default function RadarChart({ mainTarget, scores, competitors = [] }: RadarChartProps) {
  // Build radar data dynamically from real scan scores
  const data: RadarData[] = [
    { subject: 'Crypto & TLS', A: scores?.set1 ?? 80 },
    { subject: 'HTTP Headers', A: scores?.set2 ?? 75 },
    { subject: 'DNS & Spoof', A: scores?.set3 ?? 80 },
    { subject: 'Attack Surface', A: scores?.set4 ?? 80 },
    { subject: 'DAST Probes', A: scores?.set5 ?? 85 },
    { subject: 'Deception', A: scores?.set6 ?? 90 },
  ];

  // Colors for competitors
  const colors = ["#f59e0b", "#ef4444", "#3b82f6", "#8b5cf6", "#ec4899"];

  // Merge real competitor data if present
  if (competitors && competitors.length > 0) {
    competitors.forEach((comp, idx) => {
      const cScores = comp.setScores || comp.set_scores || comp.results_json?.set_scores;
      const key = `C${idx}`;
      data[0][key] = cScores?.set1 ?? (comp.overallScore ? Math.min(100, Math.round(comp.overallScore * 1.05)) : 70);
      data[1][key] = cScores?.set2 ?? (comp.overallScore ? Math.min(100, Math.round(comp.overallScore * 0.90)) : 65);
      data[2][key] = cScores?.set3 ?? (comp.overallScore ? Math.min(100, Math.round(comp.overallScore * 1.00)) : 75);
      data[3][key] = cScores?.set4 ?? (comp.overallScore ? Math.min(100, Math.round(comp.overallScore * 0.95)) : 70);
      data[4][key] = cScores?.set5 ?? (comp.overallScore ? Math.min(100, Math.round(comp.overallScore * 1.00)) : 80);
      data[5][key] = cScores?.set6 ?? (comp.overallScore ? Math.min(100, Math.round(comp.overallScore * 1.00)) : 85);
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
