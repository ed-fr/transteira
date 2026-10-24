// Minimal fake clamd (TCP, "z" commands terminated by NUL), enough for the server's antivirus
// client (internal/antivirus): zPING answers PONG, zINSTREAM reads the length-prefixed chunks
// and answers "stream: OK" or "stream: Eicar-Test-Signature FOUND" when the EICAR signature
// is present.
//
// Files above TT_CLAMAV_MAX_SCAN_BYTES are never sent here: the server marks them
// not_scanned_too_large by itself. maxStreamBytes additionally emulates clamd's own
// StreamMaxLength ("INSTREAM size limit exceeded. ERROR"), which the server treats the same way.
import net from 'node:net';
import { eicar } from './eicar';

/** Verdict of one INSTREAM exchange, kept for diagnostics. */
export interface ScanRecord {
  bytes: number;
  verdict: 'OK' | 'FOUND' | 'SIZE_LIMIT';
}

/** Options of the fake daemon. */
export interface FakeClamdOptions {
  /** Emulated StreamMaxLength; 0 (default) means unlimited. */
  maxStreamBytes?: number;
}

/** A running fake clamd. */
export interface FakeClamd {
  /** host:port to put in TT_CLAMAV_ADDR. */
  readonly address: string;
  /** Exchanges seen so far. */
  readonly scans: readonly ScanRecord[];
  close(): Promise<void>;
}

const signature = eicar();

/** Starts a fake clamd on 127.0.0.1 with a free port. */
export async function startFakeClamd(options: FakeClamdOptions = {}): Promise<FakeClamd> {
  const maxStream = options.maxStreamBytes ?? 0;
  const scans: ScanRecord[] = [];
  const sockets = new Set<net.Socket>();

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());

    let buf = Buffer.alloc(0);
    let streaming = false;
    let finished = false;
    const chunks: Buffer[] = [];
    let total = 0;

    const reply = (text: string): void => {
      finished = true;
      socket.end(`${text}\0`);
    };

    socket.on('data', (data: Buffer) => {
      if (finished) return;
      buf = Buffer.concat([buf, data]);
      if (!streaming) {
        const nul = buf.indexOf(0);
        if (nul < 0) return;
        const command = buf.subarray(0, nul).toString('latin1');
        buf = buf.subarray(nul + 1);
        if (command === 'zPING') return reply('PONG');
        if (command !== 'zINSTREAM') return reply('UNKNOWN COMMAND');
        streaming = true;
      }
      while (!finished && buf.length >= 4) {
        const size = buf.readUInt32BE(0);
        if (size === 0) {
          // A signature split across two chunks is still found: chunks are joined first.
          const found = Buffer.concat(chunks).includes(signature);
          scans.push({ bytes: total, verdict: found ? 'FOUND' : 'OK' });
          return reply(found ? 'stream: Eicar-Test-Signature FOUND' : 'stream: OK');
        }
        if (buf.length < 4 + size) return;
        chunks.push(buf.subarray(4, 4 + size));
        total += size;
        buf = buf.subarray(4 + size);
        if (maxStream > 0 && total > maxStream) {
          scans.push({ bytes: total, verdict: 'SIZE_LIMIT' });
          return reply('INSTREAM size limit exceeded. ERROR');
        }
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as net.AddressInfo).port;

  return {
    address: `127.0.0.1:${port}`,
    scans,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }),
  };
}
