export interface ConnectOptions {
  /** Directory for table state. Back it up — the network only holds ciphertext. */
  path: string;
  /** Unlocks local keys. Sent to the child over stdin, never on argv. */
  passphrase: string;
  /** Any one live peer, e.g. ["seed.blindrange.dev:7501"]. Gossip finds the rest. */
  bootstrap: string[];
  /** Which network to join. Anti-vandal membership check, not access control. */
  networkSecret?: string;
  issuer?: string;
  account?: string;
  /** Explicit interpreter path; overrides the bundled runtime. */
  python?: string;
}

export type Row = Record<string, unknown>;

export declare class UnsupportedError extends Error {}

export declare class Connection {
  /** Run one statement in the SQL dialect. Rejects with UnsupportedError
   *  when the engine cannot honour it; the message names why. */
  execute(stmt: string): Promise<Row[]>;
  /** Flush pending writes and end the child. Safe to call twice. */
  close(): Promise<void>;
}

export declare function connect(opts: ConnectOptions): Promise<Connection>;
