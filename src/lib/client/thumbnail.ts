/**
 * Browser-only thumbnail generation. Runs before encryption so the preview is
 * created from the plaintext locally; the resulting bytes are then encrypted
 * with the file's key (same E2EE guarantees as the original). Returns null when
 * a thumbnail can't be made (audio, decode failure, or TIMEOUT) — callers treat
 * thumbnails as optional and must never block an upload on one.
 *
 * The timeout is essential: a video the browser can't decode will otherwise
 * leave `loadeddata`/`seeked` events that never fire, hanging the whole upload.
 */
const MAX = 480; // longest edge, px
const QUALITY = 0.8;
const TIMEOUT_MS = 8000;

export async function makeThumbnail(file: File): Promise<Uint8Array | null> {
  try {
    if (file.type.startsWith('image/')) return await imageThumb(file);
    if (file.type.startsWith('video/')) return await videoThumb(file);
  } catch {
    /* optional — ignore decode failures and timeouts */
  }
  return null;
}

function timeout(ms: number): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(new Error('thumbnail timeout')), ms));
}

function fit(w: number, h: number): [number, number] {
  if (!w || !h) return [MAX, MAX];
  if (w <= MAX && h <= MAX) return [w, h];
  const r = Math.min(MAX / w, MAX / h);
  return [Math.round(w * r), Math.round(h * r)];
}

function canvasToBytes(canvas: HTMLCanvasElement): Promise<Uint8Array | null> {
  return new Promise((resolve) => {
    canvas.toBlob(
      async (blob) => resolve(blob ? new Uint8Array(await blob.arrayBuffer()) : null),
      'image/jpeg',
      QUALITY,
    );
  });
}

function onceEvent(el: HTMLMediaElement | HTMLImageElement, ev: string): Promise<void> {
  return new Promise((resolve, reject) => {
    el.addEventListener(ev, () => resolve(), { once: true });
    el.addEventListener('error', () => reject(new Error(`${ev} failed`)), { once: true });
  });
}

async function imageThumb(file: File): Promise<Uint8Array | null> {
  const url = URL.createObjectURL(file);
  const img = new Image();
  try {
    img.src = url;
    await Promise.race([timeout(TIMEOUT_MS), onceEvent(img, 'load')]);
    const [w, h] = fit(img.naturalWidth || img.width, img.naturalHeight || img.height);
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    canvas.getContext('2d')!.drawImage(img, 0, 0, w, h);
    return await canvasToBytes(canvas);
  } finally {
    img.removeAttribute('src');
    URL.revokeObjectURL(url);
  }
}

async function videoThumb(file: File): Promise<Uint8Array | null> {
  const url = URL.createObjectURL(file);
  const video = document.createElement('video');
  video.muted = true;
  video.preload = 'metadata';
  try {
    return await Promise.race([
      timeout(TIMEOUT_MS),
      (async () => {
        video.src = url;
        await onceEvent(video, 'loadeddata');
        // Grab a frame a little into the clip (avoids black intro frames).
        video.currentTime = Math.min(1, (video.duration || 2) / 2);
        await onceEvent(video, 'seeked');
        const [w, h] = fit(video.videoWidth, video.videoHeight);
        const canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        canvas.getContext('2d')!.drawImage(video, 0, 0, w, h);
        return await canvasToBytes(canvas);
      })(),
    ]);
  } finally {
    // Always stop in-flight decode/network, even on timeout.
    video.removeAttribute('src');
    video.load();
    URL.revokeObjectURL(url);
  }
}
