import { PcapAnalysisResult, ThreatIntel } from '../types';

export const fetchHistory = async () => {
  const response = await fetch('/api/history');
  if (!response.ok) throw new Error('Failed to fetch history');
  return response.json();
};

export const checkCache = async (hash: string) => {
  const response = await fetch(`/api/check-cache/${hash}`);
  if (!response.ok) throw new Error('Failed to check cache');
  return response.json();
};

export const cacheResult = async (data: {
  hash: string;
  filename: string;
  analysis: PcapAnalysisResult;
  intel: ThreatIntel;
  classification: string;
  attack_name: string | null;
  cve_tags: string[];
  forensic_justification: string | null;
}) => {
  const response = await fetch('/api/cache', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('Failed to cache result');
  return response.json();
};

export const deleteHistoryItem = async (hash: string) => {
  const response = await fetch(`/api/history/${hash}`, {
    method: 'DELETE',
  });
  if (!response.ok) throw new Error('Failed to delete history item');
  return response.json();
};
