// app/api/investigate/route.ts
// Server-Sent Events endpoint for the investigation pipeline
// Streams progress events to the UI in real-time as each step completes

import { NextRequest } from 'next/server';
import type { InvestigationStep } from '@/types';

export const runtime = 'nodejs';
export const maxDuration = 120; // 2 minutes max for investigation

export async function POST(req: NextRequest) {
  const { findingId } = await req.json();

  if (!findingId) {
    return new Response(JSON.stringify({ error: 'findingId is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Check environment configuration up-front
  const sanityConfigured = !!(process.env.SANITY_PROJECT_ID || process.env.NEXT_PUBLIC_SANITY_PROJECT_ID);
  if (!sanityConfigured) {
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({
          type: 'error',
          error: 'Sanity is not configured. Please set SANITY_PROJECT_ID in .env.local and run npm run seed.',
        })}\n\n`));
        controller.close();
      },
    });
    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      },
    });
  }

  // Return Server-Sent Events stream
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: object) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        } catch {
          // Stream may have been closed
        }
      };

      try {
        // Dynamically import to avoid startup errors when env not configured
        const { runInvestigation } = await import('@/lib/agent/investigationAgent');

        // Stream investigation steps as they happen
        const onStep = (step: InvestigationStep) => {
          send({ type: 'step', step });
        };

        const result = await runInvestigation(findingId, onStep);

        // Send the final result
        send({ type: 'complete', result });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Investigation failed';
        console.error('[/api/investigate]', err);
        send({ type: 'error', error: message });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
