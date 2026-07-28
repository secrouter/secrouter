/**
 * Authentication errors. `code` is a stable, non-sensitive token suitable for
 * audit logs and is never echoed verbatim to the client (we return a generic
 * 401 to avoid leaking which check failed — SI/non-leaking errors).
 */
export class AuthError extends Error {
  constructor(
    public readonly code: string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "AuthError";
  }
}
