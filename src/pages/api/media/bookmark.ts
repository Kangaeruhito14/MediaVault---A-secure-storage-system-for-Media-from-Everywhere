import type { APIRoute } from 'astro';
import { isAuthenticated } from '../../../lib/auth';
import { toggleBookmark } from '../../../lib/storage';

export const POST: APIRoute = async ({ request }) => {
  if (!isAuthenticated(request)) {
    return new Response(JSON.stringify({ error: 'Unauthorized.' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let body: { id?: string };
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { id } = body;
  if (!id) {
    return new Response(JSON.stringify({ error: 'Missing media ID.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const result = toggleBookmark(id);
  if (!result.success) {
    return new Response(JSON.stringify({ error: result.error }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ ok: true, bookmarked: result.bookmarked }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
