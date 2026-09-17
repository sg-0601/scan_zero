import { LucideIcon } from "lucide-react";
import HealingShield from "./HealingShield";

interface CategoryScore {
  name: string;
  score: number;
}

export default function ScoreGauge({ score, categories }: { score: number, categories: CategoryScore[] }) {
  const getColorClass = (val: number) => {
    if (val >= 80) return "bg-emerald-400";
    if (val >= 60) return "bg-yellow-400";
    if (val >= 40) return "bg-orange-400";
    return "bg-red-400";
  };

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-6 glow-card flex flex-col md:flex-row items-center gap-10 shadow-sm">
      <div className="flex-shrink-0">
        <HealingShield score={score} />
      </div>
      
      <div className="flex-1 w-full flex flex-col gap-4">
        <h3 className="text-lg font-medium text-gray-600">Category Breakdown</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {categories.map((cat, i) => (
            <div key={i} className="bg-gray-50 rounded-lg p-4 border border-gray-200">
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium text-gray-800">{cat.name}</span>
                <span className="text-sm font-bold text-gray-500">{cat.score}/100</span>
              </div>
              <div className="h-2 w-full bg-gray-200 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full ${getColorClass(cat.score)} transition-all duration-1000`}
                  style={{ width: `${cat.score}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
