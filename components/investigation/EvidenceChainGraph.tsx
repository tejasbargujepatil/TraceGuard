'use client';

// Evidence Chain Graph — React Flow visualization of the investigation chain
// Fixed: useNodesState/useEdgesState now reset when props change

import { useCallback, useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  MarkerType,
  Position,
  Handle,
  useReactFlow,
  ReactFlowProvider,
} from 'reactflow';
import 'reactflow/dist/style.css';
import type { ChainNode, ChainEdge } from '@/types';
import { severityColor } from '@/lib/utils';

// ─── Custom Node Component ───────────────────────────────────────────────────

const nodeTypeIcons: Record<string, string> = {
  finding: '🚨',
  asset: '🖥️',
  environment: '🌐',
  data: '🗃️',
  control: '🛡️',
  threat: '☠️',
  impact: '⚡',
  remediation: '🔧',
  policy: '📋',
};

const nodeTypeBg: Record<string, string> = {
  finding: '#1a0a0a',
  asset: '#0a1020',
  environment: '#0a1520',
  data: '#100a1a',
  control: '#051020',
  threat: '#1a0505',
  impact: '#1a0808',
  remediation: '#051a0a',
  policy: '#100f05',
};

const nodeTypeBorder: Record<string, string> = {
  finding: '#7f1d1d',
  asset: '#1e3a5f',
  environment: '#164e63',
  data: '#4c1d95',
  control: '#1e3a5f',
  threat: '#7c2d12',
  impact: '#991b1b',
  remediation: '#14532d',
  policy: '#713f12',
};

function ChainNodeComponent({ data, selected }: { data: ChainNode; selected?: boolean }) {
  return (
    <div
      style={{
        background: nodeTypeBg[data.type] || '#111827',
        border: `1.5px solid ${selected ? '#3b82f6' : nodeTypeBorder[data.type] || '#374151'}`,
        borderRadius: 10,
        padding: '10px 14px',
        minWidth: 160,
        maxWidth: 200,
        boxShadow: selected ? '0 0 0 2px rgba(59,130,246,0.3)' : '0 2px 12px rgba(0,0,0,0.5)',
        cursor: 'pointer',
        transition: 'all 0.15s ease',
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: '#374151', border: 'none', width: 6, height: 6 }} />

      <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4, fontWeight: 600 }}>
        {nodeTypeIcons[data.type] || '●'} {data.type}
      </div>

      <div style={{ fontSize: 12, color: '#e2e8f0', fontWeight: 600, lineHeight: 1.3, marginBottom: 2, wordBreak: 'break-word' }}>
        {data.label}
      </div>

      {data.sublabel && (
        <div style={{ fontSize: 10, color: '#94a3b8', lineHeight: 1.3 }}>
          {data.sublabel}
        </div>
      )}

      {data.severity && data.severity !== 'info' && (
        <div style={{
          position: 'absolute',
          top: 8,
          right: 8,
          width: 7,
          height: 7,
          borderRadius: '50%',
          backgroundColor: severityColor(data.severity),
          boxShadow: `0 0 6px ${severityColor(data.severity)}80`,
        }} />
      )}

      <Handle type="source" position={Position.Bottom} style={{ background: '#374151', border: 'none', width: 6, height: 6 }} />
    </div>
  );
}

const nodeTypes = { chain: ChainNodeComponent };

// ─── Inner graph (must be inside ReactFlowProvider) ──────────────────────────

interface InnerGraphProps {
  nodes: ChainNode[];
  edges: ChainEdge[];
  onNodeClick?: (node: ChainNode) => void;
}

function InnerGraph({ nodes, edges, onNodeClick }: InnerGraphProps) {
  const { fitView } = useReactFlow();

  const rfNodes: Node[] = useMemo(() =>
    nodes.map((node, i) => ({
      id: node.id,
      type: 'chain',
      position: { x: 240, y: i * 120 + 20 },
      data: node,
      draggable: true,
    })),
    [nodes]
  );

  const rfEdges: Edge[] = useMemo(() =>
    edges.map((e, i) => ({
      id: `edge-${i}`,
      source: e.from,
      target: e.to,
      label: e.label,
      labelStyle: { fill: '#64748b', fontSize: 10 },
      labelBgStyle: { fill: 'transparent' },
      style: { stroke: '#2a3d5e', strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#2a3d5e' },
      animated: false,
    })),
    [edges]
  );

  // Fit view whenever nodes change
  useEffect(() => {
    if (rfNodes.length > 0) {
      setTimeout(() => fitView({ padding: 0.3 }), 100);
    }
  }, [rfNodes, fitView]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (onNodeClick) onNodeClick(node.data as ChainNode);
    },
    [onNodeClick]
  );

  if (nodes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-slate-600">
          <div className="text-3xl mb-2">🔍</div>
          <div className="text-sm">Evidence chain will appear after investigation</div>
        </div>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={rfNodes}
      edges={rfEdges}
      onNodeClick={handleNodeClick}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.3 }}
      proOptions={{ hideAttribution: true }}
      style={{ background: 'transparent' }}
    >
      <Background color="#1a2540" gap={24} size={1} />
      <Controls
        style={{
          background: '#0f1629',
          border: '1px solid #1e2d4a',
          borderRadius: 8,
          color: '#94a3b8',
        }}
      />
      <MiniMap
        style={{ background: '#0a0f1a', border: '1px solid #1e2d4a' }}
        nodeColor={(n) => nodeTypeBorder[n.data?.type] || '#374151'}
      />
    </ReactFlow>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

interface EvidenceChainGraphProps {
  nodes: ChainNode[];
  edges: ChainEdge[];
  onNodeClick?: (node: ChainNode) => void;
}

export function EvidenceChainGraph({ nodes, edges, onNodeClick }: EvidenceChainGraphProps) {
  if (nodes.length === 0) {
    return (
      <div
        className="rounded-lg flex items-center justify-center"
        style={{ height: '100%', backgroundColor: '#080d18', border: '1px solid var(--border)', borderRadius: 8 }}
      >
        <div className="text-center text-slate-600">
          <div className="text-3xl mb-2">🔍</div>
          <div className="text-sm">Evidence chain will appear after investigation</div>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{ height: '100%', backgroundColor: '#080d18', border: '1px solid var(--border)', borderRadius: 8 }}
    >
      <ReactFlowProvider>
        <InnerGraph nodes={nodes} edges={edges} onNodeClick={onNodeClick} />
      </ReactFlowProvider>
    </div>
  );
}
