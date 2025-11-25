import struct
from aes import AES


class AES_GCM(object):
    """
    AES-GCM (Galois/Counter Mode) authenticated encryption implementation.

    This class provides:
      - Authenticated encryption: encrypts plaintext and produces a ciphertext + authentication tag.
      - Authenticated decryption: verifies the tag and returns plaintext if authentication succeeds.

    The construction follows the NIST GCM specification:
      - Block cipher: AES in ECB mode (used internally).
      - Encryption: AES-CTR using a counter derived from the IV.
      - Authentication: GHASH over AAD (A), ciphertext (C), and their lengths, keyed by H = E_K(0^128).
    """

    def __init__(self, key: bytes, IV: bytes, A: bytes, tag_len: int = 16) -> None:
        """
        Initialize the AES-GCM context.

        Parameters
        ----------
        key : bytes
            AES key (16, 24, or 32 bytes depending on AES-128/192/256).
        IV : bytes
            Initialization vector (nonce). Typically 12 bytes for standard GCM.
        A : bytes
            Additional Authenticated Data (AAD). This data is authenticated
            but not encrypted.
        tag_len : int, optional
            Length of the authentication tag in bytes. Commonly 16 (full 128-bit tag),
            but can be shorter (e.g., 12, 8) depending on security requirements.

        Notes
        -----
        - The AES engine is assumed to perform raw ECB encryption on 16-byte blocks.
        - The hash subkey H is computed as H = AES_K(0^128) and is used by GHASH.
        """
        self._key = key
        self._IV = IV
        self._A = A  # AAD
        self._tag_len = tag_len
        self.aes = AES(key)

        # Hash subkey H = E_K(0^128)
        self.H = self._aes_encrypt(b'\x00' * 16)

    def _aes_encrypt(self, block: bytes) -> bytes:
        """
        Encrypt a single 16-byte block using AES in ECB mode.

        Parameters
        ----------
        block : bytes
            A 16-byte input block.

        Returns
        -------
        bytes
            The 16-byte ciphertext block: AES_K(block).

        Notes
        -----
        This is a low-level wrapper around the underlying AES implementation.
        It does not perform any padding or mode logic.
        """
        return self.aes.encrypt(block)

    def mul(self, x: bytes, y: bytes) -> bytes:
        """
        Multiply two 128-bit elements in GF(2^128) using the GCM reduction polynomial.

        Parameters
        ----------
        x : bytes
            16-byte value representing an element of GF(2^128).
        y : bytes
            16-byte value representing an element of GF(2^128).

        Returns
        -------
        bytes
            The 16-byte product z = x * y in GF(2^128), reduced modulo
            the polynomial x^128 + x^7 + x^2 + x + 1.

        Notes
        -----
        - Implements the standard GCM field multiplication.
        - Uses bit-serial multiplication followed by reduction with
          the constant R = 0xE1 || 120 zero bits.
        """
        a = int.from_bytes(x, 'big')
        b = int.from_bytes(y, 'big')

        # R = 0xE1|120 bit 0 (GCM reduction constant)
        R = 0xE1000000000000000000000000000000

        z = 0
        v = b
        MASK_128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        for i in range(128):
            # Process bits of 'a' from MSB to LSB
            if (a >> (127 - i)) & 1:
                z ^= v

            # Right shift v; if LSB was 1, XOR with R
            if v & 1:
                v = (v >> 1) ^ R
            else:
                v >>= 1

        z &= MASK_128
        return z.to_bytes(16, 'big')

    def ghash_func(self, x: bytes, H: bytes) -> bytes:
        """
        Compute GHASH_H(X) over a sequence of 16-byte blocks.

        Parameters
        ----------
        x : bytes
            Input data arranged conceptually as a sequence of 16-byte blocks.
            This is typically:
              - A || pad(A) || C || pad(C) || len(A)_64 || len(C)_64 for tag computation,
              - or IV-related data for computing J0 when IV is not 96 bits.
        H : bytes
            The 16-byte hash subkey H = E_K(0^128).

        Returns
        -------
        bytes
            The 16-byte GHASH value Y_m, where:
              Y_0 = 0^128
              Y_i = (Y_{i-1} XOR X_i) * H in GF(2^128).

        Notes
        -----
        The input length must be a multiple of 16. If not, padding must be handled
        before calling this function.
        """
        y = b'\x00' * 16
        num_blocks = len(x) // 16

        for i in range(num_blocks):
            block = x[i * 16: (i + 1) * 16]
            y = self._xor(y, block)
            y = self.mul(y, H)

        return y

    def GCTR(self, icb: bytes, x: bytes) -> bytes:
        """
        Apply the GCTR function (AES-CTR) starting from an initial counter block.

        Parameters
        ----------
        icb : bytes
            Initial counter block (16 bytes). For GCM, this is typically J0 + 1
            (incremented in the least significant 32 bits).
        x : bytes
            Input data to be processed (plaintext or ciphertext).

        Returns
        -------
        bytes
            Output of the GCTR function:
              - If x is plaintext, the result is ciphertext.
              - If x is ciphertext, the result is plaintext.

        Notes
        -----
        GCTR is symmetric: applying it twice with the same icb and key yields the
        original input.
        """
        if not x:
            return b''

        n = (len(x) + 15) // 16
        cb = icb
        out = b''

        for i in range(n):
            chunk = x[i * 16: (i + 1) * 16]
            keystream = self._aes_encrypt(cb)
            y = self._xor(chunk, keystream[:len(chunk)])
            out += y
            cb = self.incre_func(cb)

        return out

    def _compute_J0(self) -> bytes:
        """
        Compute the GCM initial counter block J0 from the IV.

        Returns
        -------
        bytes
            A 16-byte block J0 defined as:
              - If len(IV) == 12 bytes (96 bits):
                    J0 = IV || 0x00000001
              - Otherwise:
                    J0 = GHASH_H(IV || pad(IV) || 0^64 || [len(IV)]_64)

        Notes
        -----
        This is the standard GCM procedure for deriving the starting counter
        block from the IV. J0 is later used both for:
          - the authentication tag computation, and
          - deriving the counter block for encryption (J1 = J0 + 1).
        """
        if len(self._IV) == 12:
            return self._IV + b'\x00\x00\x00\x01'

        len_iv_bits = len(self._IV) * 8
        pad_len = (16 - (len(self._IV) % 16)) % 16
        s_block = (
            self._IV +
            b'\x00' * pad_len +
            b'\x00' * 8 +
            struct.pack('>Q', len_iv_bits)
        )
        return self.ghash_func(s_block, self.H)

    def _calc_auth_tag(self, cipher: bytes, J0: bytes) -> bytes:
        """
        Compute the authentication tag for ciphertext and AAD.

        Parameters
        ----------
        cipher : bytes
            Ciphertext C over which authentication is computed.
        J0 : bytes
            Initial counter block J0 derived from the IV.

        Returns
        -------
        bytes
            Authentication tag T of length `self._tag_len` bytes.

        Notes
        -----
        The tag is computed as:
          1. Construct X = A || pad(A) || C || pad(C) || len(A)_64 || len(C)_64
          2. S = GHASH_H(X)
          3. Tag_full = GCTR(J0, S) = AES_K(J0) XOR S
          4. Tag = leftmost tag_len bytes of Tag_full
        """
        u = (16 - (len(cipher) % 16)) % 16
        v = (16 - (len(self._A) % 16)) % 16

        len_A_bits = len(self._A) * 8
        len_C_bits = len(cipher) * 8

        A_gen = (
            self._A + b'\x00' * v +
            cipher + b'\x00' * u +
            struct.pack('>Q', len_A_bits) +
            struct.pack('>Q', len_C_bits)
        )

        S = self.ghash_func(A_gen, self.H)
        tag_block = self.GCTR(J0, S)  # E_K(J0) XOR S via GCTR
        return tag_block[:self._tag_len]

    def encrypt_gcm(self, plaintext: bytes):
        """
        Encrypt a plaintext using AES-GCM and compute its authentication tag.

        Parameters
        ----------
        plaintext : bytes
            The plaintext data to be encrypted.

        Returns
        -------
        tuple[bytes, bytes]
            A pair (ciphertext, tag) where:
              - ciphertext : bytes
                  The encrypted data of the same length as plaintext.
              - tag : bytes
                  Authentication tag of length `self._tag_len` bytes.

        Notes
        -----
        Steps:
          1. Compute J0 from the IV.
          2. Set J1 = increment(J0) in the least significant 32 bits.
          3. C = GCTR(J1, P)  (CTR encryption).
          4. Tag = _calc_auth_tag(C, J0).
        """
        J0 = self._compute_J0()

        # Step 1: Encrypt plaintext using CTR starting from J0+1
        J1 = self.incre_func(J0)
        ciphertext = self.GCTR(J1, plaintext)

        # Step 2: Compute authentication tag
        tag = self._calc_auth_tag(ciphertext, J0)
        return ciphertext, tag

    def decrypt_gcm(self, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Decrypt a ciphertext using AES-GCM and verify its authentication tag.

        Parameters
        ----------
        ciphertext : bytes
            Ciphertext to decrypt.
        tag : bytes
            Authentication tag received along with the ciphertext.

        Returns
        -------
        bytes
            The decrypted plaintext if authentication succeeds.

        Raises
        ------
        ValueError
            If the computed authentication tag does not match the provided tag,
            indicating tampering, incorrect key, or incorrect IV/AAD.

        Notes
        -----
        Steps:
          1. Recompute J0 from the IV.
          2. Compute expected_tag = _calc_auth_tag(C, J0).
          3. Compare expected_tag with the provided tag.
             - If mismatch: raise ValueError.
             - If equal: proceed.
          4. Decrypt: P = GCTR(J1, C) with J1 = J0 + 1.
        """
        J0 = self._compute_J0()
        expected_tag = self._calc_auth_tag(ciphertext, J0)[:len(tag)]

        if expected_tag != tag:
            raise ValueError("GCM authentication failed: tag mismatch")

        J1 = self.incre_func(J0)
        decrypted = self.GCTR(J1, ciphertext)
        return decrypted

    @staticmethod
    def _xor(a: bytes, b: bytes) -> bytes:
        """
        Compute the bitwise XOR of two byte strings.

        Parameters
        ----------
        a : bytes
            First operand.
        b : bytes
            Second operand.

        Returns
        -------
        bytes
            A new bytes object where each byte is the XOR of the corresponding
            bytes in 'a' and 'b'.

        Notes
        -----
        The two inputs are zipped; if they have different lengths, the result
        length will be that of the shorter input.
        """
        return bytes([x ^ y for x, y in zip(a, b)])

    @staticmethod
    def incre_func(X: bytes) -> bytes:
        """
        Increment the least significant 32 bits of a 16-byte counter block.

        Parameters
        ----------
        X : bytes
            16-byte counter block. The most significant 96 bits act as a fixed
            prefix (nonce part), and the least significant 32 bits are treated
            as a big-endian integer counter.

        Returns
        -------
        bytes
            A new 16-byte counter block where the last 32 bits have been
            incremented modulo 2^32 (wrap-around semantics).

        Notes
        -----
        This is the standard way GCM increments the counter portion of the
        block when the IV is 96 bits:
            X = IV || counter_32
        """
        iv_part = X[:-4]
        counter_part = struct.unpack('>I', X[-4:])[0]
        counter_part = (counter_part + 1) & 0xFFFFFFFF
        return iv_part + struct.pack('>I', counter_part)
