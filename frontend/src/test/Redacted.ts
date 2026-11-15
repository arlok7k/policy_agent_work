/** Ephemeral test secret that does not reveal its value in diagnostic output. */
export class Redacted {
  readonly #value: string;
  constructor(value: string) { this.#value = value; }
  static random(): Redacted { return new Redacted(crypto.randomUUID() + crypto.randomUUID()); }
  reveal(): string { return this.#value; }
  toString(): string { return '<redacted>'; }
  toJSON(): string { return '<redacted>'; }
}
