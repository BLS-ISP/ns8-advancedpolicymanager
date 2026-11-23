export function randomBytes(size) {
  const bytes = new Uint8Array(size);
  if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(bytes);
  }
  return bytes;
}

export default {
  randomBytes,
};
