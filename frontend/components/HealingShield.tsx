"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";

export default function HealingShield({ score, grade }: { score: number; grade?: string }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let current = 0;
    const interval = setInterval(() => {
      if (current < score) {
        current += 1;
        setAnimatedScore(current);
      } else {
        clearInterval(interval);
      }
    }, 20);
    return () => clearInterval(interval);
  }, [score]);

  const getColor = (val: number) => {
    if (val >= 80) return "#34d399"; // emerald
    if (val >= 60) return "#fbbf24"; // yellow
    if (val >= 40) return "#f97316"; // orange
    return "#ef4444"; // red
  };

  const getGrade = (val: number) => {
    if (val >= 90) return "A+";
    if (val >= 80) return "A";
    if (val >= 70) return "B";
    if (val >= 60) return "C";
    if (val >= 50) return "D";
    return "F";
  };

  const color = getColor(animatedScore);
  const radius = 90;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="relative flex items-center justify-center w-64 h-64">
      {/* Background track */}
      <svg className="w-full h-full transform -rotate-90">
        <circle
          cx="128"
          cy="128"
          r={radius}
          stroke="currentColor"
          strokeWidth="16"
          fill="transparent"
          className="text-gray-200"
        />
        {/* Animated progress */}
        <motion.circle
          cx="128"
          cy="128"
          r={radius}
          stroke={color}
          strokeWidth="16"
          fill="transparent"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          strokeLinecap="round"
          style={{
            filter: `drop-shadow(0 0 10px ${color}80)`
          }}
        />
      </svg>
      
      {/* Center text */}
      <div className="absolute flex flex-col items-center justify-center">
        <span className="text-5xl font-black text-gray-900">{animatedScore}%</span>
        <div 
          className="mt-2 px-4 py-1 rounded-full text-lg font-bold shadow-sm"
          style={{ backgroundColor: `${color}40`, color, border: `1px solid ${color}80` }}
        >
          Grade {grade || getGrade(animatedScore)}
        </div>
      </div>
    </div>
  );
}
