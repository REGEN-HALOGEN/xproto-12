import { useMemo } from 'react';
import type { Node, Edge } from '@xyflow/react';
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { EngineEvent } from '../types';

interface ChainDiagramProps {
  events: EngineEvent[];
  defenseOn: boolean;
}

export const ChainDiagram: React.FC<ChainDiagramProps> = ({ events, defenseOn }) => {
  // Analyze latest events to determine active chain state and decisions
  const state = useMemo(() => {
    let latestDecision: { allowed: boolean; reason: string; tool?: string } | null = null;
    let hasToolCall = false;
    let hasDelegation = false;
    let activeTool = 'read_file';
    let chainAuthority = defenseOn ? 'LOW' : 'HIGH';

    for (const ev of events) {
      if (ev.event === 'tool_call') {
        hasToolCall = true;
        if (ev.data.tool) activeTool = String(ev.data.tool);
      } else if (ev.event === 'delegation') {
        hasDelegation = true;
      } else if (ev.event === 'xgate_decision') {
        latestDecision = {
          allowed: Boolean(ev.data.allowed),
          reason: String(ev.data.reason || ''),
          tool: String(ev.data.tool || activeTool),
        };
        if (ev.data.chain_authority) {
          chainAuthority = String(ev.data.chain_authority);
        }
      }
    }

    return { latestDecision, hasToolCall, hasDelegation, activeTool, chainAuthority };
  }, [events, defenseOn]);

  const nodes: Node[] = useMemo(() => {
    const isDenied = state.latestDecision && !state.latestDecision.allowed;
    const isAllowed = state.latestDecision && state.latestDecision.allowed;

    return [
      {
        id: 'initiator',
        position: { x: 40, y: 120 },
        data: {
          label: (
            <div className="p-3 bg-[#0d1117] border border-[#30363d] rounded-lg text-left shadow-lg">
              <div className="flex items-center justify-between space-x-2">
                <span className="text-[10px] uppercase font-mono text-slate-400">Principal</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 font-mono font-bold">
                  HIGH
                </span>
              </div>
              <div className="text-xs font-bold text-white mt-1">Initiator (User)</div>
              <div className="text-[10px] text-slate-400 font-mono">owner@victim</div>
            </div>
          ),
        },
        draggable: false,
      },
      {
        id: 'victim',
        position: { x: 260, y: 120 },
        data: {
          label: (
            <div className={`p-3 bg-[#0d1117] border rounded-lg text-left shadow-lg ${
              isDenied
                ? 'border-rose-500/80 shadow-[0_0_15px_rgba(244,63,94,0.3)]'
                : 'border-[#30363d]'
            }`}>
              <div className="flex items-center justify-between space-x-2">
                <span className="text-[10px] uppercase font-mono text-slate-400">Agent</span>
                <span
                  className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold ${
                    defenseOn
                      ? 'bg-sky-950 text-sky-400 border border-sky-500/30'
                      : 'bg-amber-950 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  {defenseOn ? 'CHAIN: LOW' : 'VULNERABLE: HIGH'}
                </span>
              </div>
              <div className="text-xs font-bold text-white mt-1">Victim Agent</div>
              <div className="text-[10px] text-slate-400 font-mono">A2A Endpoint :18080</div>
            </div>
          ),
        },
        draggable: false,
      },
      {
        id: 'peer',
        position: { x: 480, y: 40 },
        data: {
          label: (
            <div className="p-3 bg-[#0d1117] border border-[#30363d] rounded-lg text-left shadow-lg">
              <div className="flex items-center justify-between space-x-2">
                <span className="text-[10px] uppercase font-mono text-slate-400">Relay / Peer</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-sky-950 text-sky-400 font-mono font-bold">
                  LOW
                </span>
              </div>
              <div className="text-xs font-bold text-white mt-1">Attested Peer</div>
              <div className="text-[10px] text-slate-400 font-mono">relay / archiver</div>
            </div>
          ),
        },
        draggable: false,
      },
      {
        id: 'mcp_tool',
        position: { x: 500, y: 190 },
        data: {
          label: (
            <div
              className={`p-3 bg-[#0d1117] border rounded-lg text-left shadow-lg transition-all ${
                isDenied
                  ? 'border-rose-500 shadow-[0_0_20px_rgba(244,63,94,0.4)]'
                  : isAllowed
                  ? 'border-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.3)]'
                  : 'border-[#30363d]'
              }`}
            >
              <div className="flex items-center justify-between space-x-2">
                <span className="text-[10px] uppercase font-mono text-slate-400">Tool / Sink</span>
                <span
                  className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold ${
                    isDenied
                      ? 'bg-rose-950 text-rose-400 border border-rose-500/40'
                      : isAllowed
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {isDenied ? 'BLOCKED' : isAllowed ? 'EXECUTED' : 'REQUIRED: HIGH'}
                </span>
              </div>
              <div className="text-xs font-bold text-white mt-1">{state.activeTool}</div>
              <div className="text-[10px] text-slate-400 font-mono">MCP Stdio Client</div>
            </div>
          ),
        },
        draggable: false,
      },
    ];
  }, [state, defenseOn]);

  const edges: Edge[] = useMemo(() => {
    const isDenied = state.latestDecision && !state.latestDecision.allowed;
    const isAllowed = state.latestDecision && state.latestDecision.allowed;

    const list: Edge[] = [
      {
        id: 'e-initiator-victim',
        source: 'initiator',
        target: 'victim',
        animated: true,
        style: { stroke: '#0284c7', strokeWidth: 2 },
        label: 'A2A Task',
        labelStyle: { fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#0284c7' },
      },
    ];

    if (state.hasDelegation) {
      list.push({
        id: 'e-victim-peer',
        source: 'victim',
        target: 'peer',
        animated: true,
        style: { stroke: '#38bdf8', strokeWidth: 2 },
        label: 'Delegate',
        labelStyle: { fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#38bdf8' },
      });
    }

    // Edge from victim to tool
    list.push({
      id: 'e-victim-tool',
      source: 'victim',
      target: 'mcp_tool',
      animated: isAllowed || (!isDenied && state.hasToolCall),
      style: {
        stroke: isDenied ? '#f43f5e' : isAllowed ? '#10b981' : '#64748b',
        strokeWidth: isDenied || isAllowed ? 3 : 2,
      },
      label: isDenied
        ? 'DENIED (Authority Violation)'
        : isAllowed
        ? 'ALLOWED (Authorized)'
        : 'MCP Tool Call',
      labelStyle: {
        fill: isDenied ? '#f43f5e' : isAllowed ? '#10b981' : '#94a3b8',
        fontWeight: isDenied || isAllowed ? 'bold' : 'normal',
        fontSize: 10,
        fontFamily: 'monospace',
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: isDenied ? '#f43f5e' : isAllowed ? '#10b981' : '#64748b',
      },
    });

    return list;
  }, [state]);

  return (
    <div className="h-full w-full bg-[#090a0f] relative overflow-hidden">
      <div className="absolute top-3 left-3 z-10 flex items-center space-x-2 bg-[#0d1117]/80 backdrop-blur-sm border border-[#21262d] px-2.5 py-1 rounded-md text-[11px] text-slate-300">
        <span className="w-2 h-2 rounded-full bg-sky-400" />
        <span className="font-semibold">Principal Chain Graph</span>
      </div>

      {state.latestDecision && (
        <div
          className={`absolute top-3 right-3 z-10 px-3 py-1.5 rounded-md border text-xs font-mono font-semibold flex items-center space-x-2 shadow-lg backdrop-blur-sm ${
            state.latestDecision.allowed
              ? 'bg-emerald-950/80 border-emerald-500/50 text-emerald-300'
              : 'bg-rose-950/80 border-rose-500/50 text-rose-300'
          }`}
        >
          <span>{state.latestDecision.allowed ? '✓ ALLOWED' : '⛔ DENIED by XGate'}</span>
          <span className="text-[10px] text-slate-300 font-normal">
            ({state.latestDecision.reason})
          </span>
        </div>
      )}

      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        panOnDrag={false}
        zoomOnScroll={false}
        nodesDraggable={false}
        className="bg-[#090a0f]"
      >
        <Background color="#161b22" gap={20} size={1} />
        <Controls showInteractive={false} className="bg-[#161b22] border-[#30363d] fill-slate-300" />
      </ReactFlow>
    </div>
  );
};
