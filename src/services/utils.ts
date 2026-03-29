export const calculateHash = async (file: File): Promise<string> => {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

export const getHostStyle = (ip: string) => {
  if (ip.includes(':')) return 'bg-indigo-500/20 border-indigo-500/40 text-indigo-200'; // IPv6

  const parts = ip.split('.').map(n => parseInt(n, 10));
  if (parts.length !== 4) return 'bg-gray-500/20 border-gray-500/40 text-gray-300';

  // Private ranges
  if (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  ) {
    return 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'; // Private (Internal)
  }

  // Loopback
  if (parts[0] === 127) return 'bg-slate-500/20 border-slate-500/40 text-slate-400';

  // Multicast
  if (parts[0] >= 224 && parts[0] <= 239) return 'bg-purple-500/20 border-purple-500/40 text-purple-300';

  // Public (Default)
  return 'bg-sky-500/20 border-sky-500/40 text-sky-300';
};
