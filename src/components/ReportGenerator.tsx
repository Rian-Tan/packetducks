import React from 'react';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { PcapAnalysisResult, ThreatIntel } from '../types';
import { Download } from 'lucide-react';

interface ReportGeneratorProps {
  analysis: PcapAnalysisResult;
  threatIntel: ThreatIntel;
  chartElementId: string;
}

const ReportGenerator: React.FC<ReportGeneratorProps> = ({ 
  analysis, 
  threatIntel,
  chartElementId,
}) => {

  const generateReport = async () => {
    const chartElement = document.getElementById(chartElementId);

    if (!chartElement) {
      console.error('Chart element for PDF generation not found');
      return;
    }

    try {
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 15;
      const footerHeight = 20;
      let currentY = 0;

      const addPageIfNeeded = () => {
        if (currentY > pageHeight - footerHeight) {
          pdf.addPage();
          currentY = margin;
        }
      }

      // --- Header --- 
      pdf.setFillColor(17, 24, 39); // bg-gray-900
      pdf.rect(0, 0, pageWidth, 30, 'F');
      pdf.setFontSize(24);
      pdf.setTextColor(255, 255, 255);
      pdf.setFont('helvetica', 'bold');
      pdf.text('PacketDuck Analysis Report', margin, 18);
      currentY = 30;

      // --- Summary --- 
      currentY += 15;
      pdf.setFontSize(18);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(55, 65, 81); 
      pdf.text('Analysis Summary', margin, currentY);
      
      currentY += 7;
      pdf.setFontSize(11);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(107, 114, 128);
      pdf.text(`Report Generated: ${new Date().toLocaleString()}`, margin, currentY);
      
      currentY += 13;
      const summaryBoxWidth = (pageWidth - margin * 2) / 4 - 5;
      const summaryData = [
        { label: 'Total Packets', value: analysis.totalPackets.toLocaleString() },
        { label: 'Conversations', value: analysis.connections.length.toLocaleString() },
        { label: 'Unique Hosts', value: analysis.uniqueHosts.length.toLocaleString() },
        { label: 'Duration (s)', value: ((analysis.endTime.getTime() - analysis.startTime.getTime()) / 1000).toFixed(2) },
      ];

      summaryData.forEach((item, index) => {
        const x = margin + index * (summaryBoxWidth + 5);
        pdf.setFillColor(243, 244, 246);
        pdf.setDrawColor(209, 213, 219);
        pdf.roundedRect(x, currentY, summaryBoxWidth, 20, 3, 3, 'FD');
        pdf.setFontSize(10);
        pdf.setTextColor(107, 114, 128);
        pdf.text(item.label, x + 5, currentY + 7);
        pdf.setFontSize(16);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(17, 24, 39);
        pdf.text(item.value, x + 5, currentY + 15);
      });
      currentY += 30;
      addPageIfNeeded();

      // --- Threat Intelligence Section ---
      pdf.setFontSize(18);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(55, 65, 81);
      pdf.text('AI Threat Assessment', margin, currentY);
      currentY += 10;
      const assessmentStartY = currentY;

      // Risk Score
      const riskScoreX = margin + 25;
      const score = threatIntel.riskScore;
      let scoreColor = '#22c55e';
      if (score > 50) scoreColor = '#f97316';
      if (score > 75) scoreColor = '#ef4444';
      pdf.setLineWidth(2);
      pdf.setDrawColor(scoreColor);
      pdf.circle(riskScoreX, currentY + 10, 15, 'D');
      pdf.setFontSize(22);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(scoreColor);
      pdf.text(score.toString(), riskScoreX, currentY + 13, { align: 'center' });
      const scoreHeight = 35;

      // AI Summary Text
      const summaryX = riskScoreX + 30;
      pdf.setFontSize(11);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(107, 114, 128);
      const summaryLines = pdf.splitTextToSize(threatIntel.summary, pageWidth - summaryX - margin);
      pdf.text(summaryLines, summaryX, currentY + 2);
      const summaryHeight = summaryLines.length * 5;
      currentY = assessmentStartY + Math.max(summaryHeight, scoreHeight);
      addPageIfNeeded();

      // --- Indicators of Compromise (IOCs) ---
      if (threatIntel.iocs.length > 0) {
        currentY += 10;
        pdf.setFontSize(18);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(55, 65, 81);
        pdf.text('Indicators of Compromise', margin, currentY);
        currentY += 10;

        threatIntel.iocs.forEach(ioc => {
          const descLines = pdf.splitTextToSize(ioc.description, pageWidth - margin * 2);
          const iocBlockHeight = 10 + (descLines.length * 4) + 5;

          if (currentY + iocBlockHeight > pageHeight - footerHeight) {
            pdf.addPage();
            currentY = margin;
          }

          pdf.setFontSize(12);
          pdf.setFont('helvetica', 'bold');
          pdf.setTextColor(31, 41, 55);
          pdf.text(ioc.value, margin, currentY);
          
          const severityColor = ioc.severity === 'CRITICAL' ? '#ef4444' : '#6b7280';
          pdf.setFontSize(8);
          pdf.setTextColor(severityColor);
          const severityWidth = pdf.getStringUnitWidth(ioc.severity) * 8 / pdf.internal.scaleFactor;
          pdf.text(ioc.severity, pageWidth - margin - severityWidth, currentY - 1);
          
          currentY += 5;
          pdf.setFontSize(9);
          pdf.setFont('helvetica', 'normal');
          pdf.setTextColor(107, 114, 128);
          pdf.text(ioc.type, margin, currentY);
          currentY += 4;
          
          pdf.setFontSize(10);
          pdf.text(descLines, margin, currentY);
          currentY += (descLines.length * 4) + 5;
        });
      }
      addPageIfNeeded();

      // --- Actionable Recommendations ---
      if (threatIntel.recommendations.length > 0) {
        currentY += 10;
        pdf.setFontSize(18);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(55, 65, 81);
        pdf.text('Actionable Recommendations', margin, currentY);
        currentY += 10;

        threatIntel.recommendations.forEach((rec, index) => {
          const recLines = pdf.splitTextToSize(rec, pageWidth - margin * 2 - 10); // Indent text
          const recBlockHeight = (recLines.length * 5) + 8;

          if (currentY + recBlockHeight > pageHeight - footerHeight) {
            pdf.addPage();
            currentY = margin;
          }
          
          pdf.setFontSize(14);
          pdf.setTextColor(31, 41, 55);
          pdf.text(`${index + 1}.`, margin, currentY);

          pdf.setFontSize(11);
          pdf.setFont('helvetica', 'normal');
          pdf.setTextColor(80, 80, 80);
          pdf.text(recLines, margin + 8, currentY);
          currentY += recBlockHeight;
        });
      }
      addPageIfNeeded();

      // --- Protocol Distribution Section ---
      currentY += 10;
      pdf.setFontSize(18);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(55, 65, 81);
      pdf.text('Protocol Distribution', margin, currentY);
      currentY += 10;

      const chartCanvas = await html2canvas(chartElement, { useCORS: true, backgroundColor: '#ffffff' });
      const chartImgData = chartCanvas.toDataURL('image/png');
      const chartImgProps = pdf.getImageProperties(chartImgData);
      const chartImgHeight = (chartImgProps.height * (pageWidth / 2 - margin * 1.5)) / chartImgProps.width;

      const statsX = pageWidth / 2 + margin / 2;
      const statsWidth = pageWidth / 2 - margin * 1.5;
      
      let statsY = currentY;
      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'bold');
      pdf.text('Statistics', statsX, statsY);
      statsY += 7;
      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'normal');

      for (const [protocol, count] of Object.entries(analysis.protocolCounts)) {
        pdf.text(`${protocol}:`, statsX, statsY);
        pdf.text(count.toLocaleString(), statsX + statsWidth - 15, statsY, { align: 'right' });
        statsY += 6;
      }

      const finalBlockHeight = Math.max(chartImgHeight, statsY - currentY);
      if (currentY + finalBlockHeight > pageHeight - footerHeight) {
        pdf.addPage();
        currentY = margin;
      }

      pdf.addImage(chartImgData, 'PNG', margin, currentY, pageWidth / 2 - margin * 1.5, chartImgHeight);
      
      // --- Footer ---
      const pageCount = pdf.internal.getNumberOfPages();
      for (let i = 1; i <= pageCount; i++) {
        pdf.setPage(i);
        const footerY = pageHeight - 10;
        pdf.setFontSize(8);
        pdf.setTextColor(156, 163, 175);
        pdf.text(`PacketDuck Analysis - ${analysis.startTime.toISOString()}`, margin, footerY);
        pdf.text(`Page ${i} of ${pageCount}`, pageWidth - margin - 15, footerY);
      }

      pdf.save(`PacketDuck_Report_${Date.now()}.pdf`);
    } catch (error) {
      console.error("Error generating PDF:", error);
    }
  };

  return (
    <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-4 flex items-center justify-center">
       <button 
        onClick={generateReport}
        className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-cyber-accent hover:bg-cyber-accent-dark text-white font-semibold rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-cyber-800 focus:ring-cyber-accent"
      >
        <Download size={18} />
        Download Report
      </button>
    </div>
  );
};

export default ReportGenerator;
