// The EICAR antivirus test signature, assembled at runtime from fragments so that the complete
// string never appears in the repository (CLAUDE.md test rules; scanners flag files holding it).

/** Returns the 68-byte EICAR test signature. */
export function eicar(): Buffer {
  const backslash = String.fromCharCode(92);
  return Buffer.from(
    ['X5O!P%@AP[4', backslash, 'PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS', '-TEST-FILE!$H+H*'].join(''),
    'latin1',
  );
}
