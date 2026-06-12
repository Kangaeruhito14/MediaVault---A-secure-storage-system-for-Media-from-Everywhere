import type { APIRoute } from 'astro';
import { isAuthenticated } from '../../../lib/auth';
import { deleteMedia } from '../../../lib/storage';

export const POST: APIRoute = async ({ request }) => {
  if (!isAuthenticated(request)) {
    return new Response(JSON.stringify({ error: 'Unauthorized.' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { ids } = body;
  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return new Response(JSON.stringify({ error: 'Missing or invalid media IDs array.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let deletedCount = 0;
  for (const id of ids) {
    const success = deleteMedia(id);
    if (success) {
      deletedCount++;
    }
  }

  return new Response(JSON.stringify({ ok: true, deletedCount }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
