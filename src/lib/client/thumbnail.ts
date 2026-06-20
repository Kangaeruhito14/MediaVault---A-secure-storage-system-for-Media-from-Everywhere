/**
 * Browser-only thumbnail generation. Runs before encryption so the preview is
 * created from the plaintext locally; the resulting bytes are then encrypted
 * with the file's key (same E2EE guarantees as the original). Returns null when
 * a thumbnail can't be made (e.g. audio, or a decode failure) — callers treat
 * thumbnails as optional.
 */
const MAX = 480; // longest edge, px
const QUALITY = 0.8;

export async function makeThumbnail(file: File): Promise<Uint8Array | null> {
  try {
    if (file.type.startsWith('image/')) return await imageThumb(file);
    if (file.type.startsWith('video/')) return await videoThumb(file);
  } catch {
    /* optional — ignore */
  }
  return null;
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

function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('image decode failed'));
    img.src = url;
  });
}

async function imageThumb(file: File): Promise<Uint8Array | null> {
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    const [w, h] = fit(img.naturalWidth || img.width, img.naturalHeight || img.height);
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    canvas.getContext('2d')!.drawImage(img, 0, 0, w, h);
    return await canvasToBytes(canvas);
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function videoThumb(file: File): Promise<Uint8Array | null> {
  const url = URL.createObjectURL(file);
  const video = document.createElement('video');
  video.muted = true;
  video.preload = 'metadata';
  try {
    video.src = url;
    await new Promise<void>((resolve, reject) => {
      video.onloadeddata = () => resolve();
      video.onerror = () => reject(new Error('video load failed'));
    });
    // Grab a frame a little into the clip (avoids black intro frames).
    video.currentTime = Math.min(1, (video.duration || 2) / 2);
    await new Promise<void>((resolve, reject) => {
      video.onseeked = () => resolve();
      video.onerror = () => reject(new Error('video seek failed'));
    });
    const [w, h] = fit(video.videoWidth, video.videoHeight);
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    canvas.getContext('2d')!.drawImage(video, 0, 0, w, h);
    return await canvasToBytes(canvas);
  } finally {
    URL.revokeObjectURL(url);
  }
}
