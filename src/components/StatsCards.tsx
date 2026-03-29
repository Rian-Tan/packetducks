import React from 'react';

interface StatsCardsProps {
  totalPackets: number;
  uniqueHostsCount: number;
  connectionsCount: number;
  duration: number;
}

export const StatsCards: React.FC<StatsCardsProps> = ({
  totalPackets,
  uniqueHostsCount,
  connectionsCount,
  duration
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <p className="text-sm text-gray-400 mb-1">Total Packets</p>
        <p className="text-2xl font-mono font-bold text-white">{totalPackets.toLocaleString()}</p>
      </div>
      <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <p className="text-sm text-gray-400 mb-1">Unique Hosts</p>
        <p className="text-2xl font-mono font-bold text-cyber-400">{uniqueHostsCount}</p>
      </div>
      <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <p className="text-sm text-gray-400 mb-1">Conversations</p>
        <p className="text-2xl font-mono font-bold text-cyber-accent">{connectionsCount}</p>
      </div>
      <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <p className="text-sm text-gray-400 mb-1">Duration</p>
        <p className="text-2xl font-mono font-bold text-white">
          {duration.toFixed(2)}s
        </p>
      </div>
    </div>
  );
};
