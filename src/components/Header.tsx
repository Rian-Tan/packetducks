import React from 'react';
import { Shield, Upload, History, FileDigit } from 'lucide-react';

interface HeaderProps {
  view: 'analyze' | 'history' | 'threats';
  setView: (view: 'analyze' | 'history' | 'threats') => void;
  fileName?: string;
}

export const Header: React.FC<HeaderProps> = ({ view, setView, fileName }) => {
  return (
    <header className="sticky top-0 z-50 bg-cyber-900/80 backdrop-blur-md border-b border-cyber-700">
      <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <Shield className="text-cyber-accent w-8 h-8" />
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">PacketDuck</h1>
              <p className="text-xs text-cyber-400 font-mono">Quacksome Packet Analyser and Threat Intelligence Dashboard</p>
            </div>
          </div>
          <nav className="hidden md:flex items-center bg-cyber-800 rounded-lg p-1 border border-cyber-700">
            <button
              onClick={() => setView('analyze')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${view === 'analyze' ? 'bg-cyber-accent text-white shadow-lg' : 'text-gray-400 hover:text-gray-200'}`}
            >
              <Upload size={16} />
              Analyze
            </button>
            <button
              onClick={() => setView('history')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${view === 'history' ? 'bg-cyber-accent text-white shadow-lg' : 'text-gray-400 hover:text-gray-200'}`}
            >
              <History size={16} />
              History
            </button>
            <button
              onClick={() => setView('threats')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${view === 'threats' ? 'bg-cyber-accent text-white shadow-lg' : 'text-gray-400 hover:text-gray-200'}`}
            >
              <Shield size={16} />
              Threat DB
            </button>
          </nav>
        </div>
        {fileName && (
          <div className="hidden sm:flex items-center gap-2 text-sm text-gray-400 bg-cyber-800 px-3 py-1.5 rounded-lg border border-cyber-700">
            <FileDigit size={14} />
            <span className="truncate max-w-[150px]">{fileName}</span>
          </div>
        )}
      </div>
    </header>
  );
};
