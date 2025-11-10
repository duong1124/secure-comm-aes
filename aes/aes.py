from .aes_helper import (expand_key, byte_to_state, add_round_key, create_round_key,
                        sub_bytes, shift_rows, mix_columns, state_to_byte,
                        inv_shift_rows, inv_sub_bytes, inv_mix_columns)


class AES:
    """Implementation of the AES encryption algorithm."""
    def __init__(self, key_size: int = 16):
        if key_size not in (16, 24, 32):
            raise ValueError("key_size must be 16, 24, or 32 (bytes).")
        self.key_size = key_size # in bytes
        self._rounds = {16: 10, 24: 12, 32: 14}[key_size]
        # self.modified_aes_512 = False  # to indicate if AES-512 is used


    def encrypt(self, input_bytes: bytearray, key: bytearray) -> bytearray:
        """Encrypt a 16-byte block with AES using the given key."""
        expanded_key = expand_key(key, self.key_size, 16 * (self._rounds + 1))
        state = byte_to_state(input_bytes)

        # Initial Round
        state = add_round_key(state, create_round_key(expanded_key, 0))

        # Main Rounds
        for round_idx in range(1, self._rounds):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, create_round_key(expanded_key, round_idx))

        # Final Round (no MixColumns)
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, create_round_key(expanded_key, self._rounds))

        return state_to_byte(state)


    def decrypt(self, input_bytes: bytearray, key: bytearray) -> bytearray:
        """Decrypt a 16-byte block with AES using the given key."""
        expanded_key = expand_key(key, self.key_size, 16 * (self._rounds + 1))
        state = byte_to_state(input_bytes)

        # Initial Round
        state = add_round_key(state, create_round_key(expanded_key, self._rounds))

        # Main Rounds
        for round_idx in range(self._rounds - 1, 0, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
            state = add_round_key(state, create_round_key(expanded_key, round_idx))
            state = inv_mix_columns(state)

        # Final Round (no InvMixColumns)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, create_round_key(expanded_key, 0))

        return state_to_byte(state)