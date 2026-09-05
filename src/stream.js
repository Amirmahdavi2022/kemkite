// A transport-agnostic byte stream. The protocol code only ever asks for
// "give me exactly N bytes" and "write these bytes", so the same modules run
// over a TCP socket in the tests and over a WebSocket inside the Worker.

export class ByteStream {
  /**
   * @param {object} sink   - { write(u8): void|Promise, close(): void }
   */
  constructor(sink) {
    this.sink = sink;
    this.chunks = [];
    this.size = 0;
    this.waiter = null;
    this.ended = false;
    this.error = null;
  }

  /** Feed inbound bytes in (called by the transport). */
  push(u8) {
    if (u8 && u8.length) {
      this.chunks.push(u8);
      this.size += u8.length;
    }
    this._wake();
  }

  end() {
    this.ended = true;
    this._wake();
  }

  fail(err) {
    this.error = err;
    this.ended = true;
    this._wake();
  }

  _wake() {
    const w = this.waiter;
    if (w) {
      this.waiter = null;
      w();
    }
  }

  _available() {
    return new Promise((resolve) => {
      this.waiter = resolve;
    });
  }

  /** Resolves with exactly n bytes, or throws if the stream ends first. */
  async readFull(n) {
    while (this.size < n) {
      if (this.error) throw this.error;
      if (this.ended) throw new Error('unexpected EOF: wanted ' + n + ', have ' + this.size);
      await this._available();
    }
    return this._take(n);
  }

  /** Resolves with whatever is buffered (at least one byte), or null at EOF. */
  async readSome() {
    while (this.size === 0) {
      if (this.error) throw this.error;
      if (this.ended) return null;
      await this._available();
    }
    return this._take(this.size);
  }

  _take(n) {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const head = this.chunks[0];
      const need = n - off;
      if (head.length <= need) {
        out.set(head, off);
        off += head.length;
        this.chunks.shift();
      } else {
        out.set(head.subarray(0, need), off);
        this.chunks[0] = head.subarray(need);
        off += need;
      }
    }
    this.size -= n;
    return out;
  }

  write(u8) {
    return this.sink.write(u8);
  }

  close() {
    try {
      this.sink.close();
    } catch {
      /* already gone */
    }
  }
}
