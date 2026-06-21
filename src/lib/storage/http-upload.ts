/**
 * XHR-based upload with real byte progress. fetch() can't report upload
 * progress in browsers, so when a caller wants a progress bar we send via
 * XMLHttpRequest (which exposes upload.onprogress) instead. Used only for the
 * upload leg; downloads/ranges stay on fetch.
 */
export interface XhrResult {
  status: number;
  text: string;
}

export type ProgressFn = (loaded: number, total: number) => void;

export const hasXhr = typeof XMLHttpRequest !== 'undefined';

export function xhrUpload(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: Uint8Array,
  onProgress?: ProgressFn,
): Promise<XhrResult> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    for (const k in headers) xhr.setRequestHeader(k, headers[k]);
    if (onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(e.loaded, e.total);
      };
    }
    xhr.onload = () => resolve({ status: xhr.status, text: xhr.responseText || '' });
    xhr.onerror = () => reject(new Error('network error'));
    xhr.ontimeout = () => reject(new Error('upload timed out'));
    xhr.send(body as unknown as XMLHttpRequestBodyInit);
  });
}
