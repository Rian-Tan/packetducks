import React from 'react';
import { Upload, FileText, AlertCircle } from 'lucide-react';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  isProcessing: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onFileSelect, isProcessing }) => {
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onFileSelect(e.target.files[0]);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto mt-12 p-6">
      <div className="relative border-2 border-dashed border-cyber-700 bg-cyber-800/50 rounded-xl p-12 text-center transition-all hover:border-cyber-500 hover:bg-cyber-800 group">
        <input
          type="file"
          accept=".pcap,.cap"
          onChange={handleFileChange}
          disabled={isProcessing}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10 disabled:cursor-not-allowed"
        />
        
        <div className="flex flex-col items-center space-y-4">
          <div className="p-4 bg-cyber-900 rounded-full border border-cyber-700 group-hover:border-cyber-500 transition-colors">
            {isProcessing ? (
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyber-accent"></div>
            ) : (
              <Upload className="w-8 h-8 text-cyber-400" />
            )}
          </div>
          
          <div className="space-y-2">
            <h3 className="text-xl font-semibold text-gray-100">
              {isProcessing ? 'Analyzing Capture...' : 'Upload PCAP File'}
            </h3>
            <p className="text-gray-400 text-sm max-w-xs mx-auto">
              Drag and drop or click to select a packet capture file (.pcap) for analysis.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs text-cyber-500 bg-cyber-900/50 px-3 py-1 rounded-full border border-cyber-700/50">
            <AlertCircle size={12} />
            <span>Files uploaded are processed in memory.</span>
          </div>
        </div>
      </div>
    </div>
  );
};