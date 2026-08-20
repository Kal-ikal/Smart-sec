/**
 * Token Bucket sederhana untuk melambatkan laju permintaan worker ke
 * target pemindaian, sesuai Batasan Masalah proposal (mencegah
 * indikasi serangan Denial of Service ke peladen target saat
 * mass-scanning).
 */
export class TokenBucket {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillPerSecond: number;
  private lastRefill: number;

  constructor(capacity: number, refillPerSecond: number) {
    this.capacity = capacity;
    this.refillPerSecond = refillPerSecond;
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  private refill() {
    const now = Date.now();
    const elapsedSeconds = (now - this.lastRefill) / 1000;
    const refillAmount = elapsedSeconds * this.refillPerSecond;
    if (refillAmount > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + refillAmount);
      this.lastRefill = now;
    }
  }

  /** Menunggu (blok async) sampai satu token tersedia, lalu mengonsumsinya. */
  async take(): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.ceil((1 - this.tokens) / this.refillPerSecond * 1000);
      await new Promise((resolve) => setTimeout(resolve, Math.max(waitMs, 50)));
    }
  }
}
