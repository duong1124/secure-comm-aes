from .aes_constant import *


def byte_to_state(block: bytearray) -> bytearray:
    """
    Convert 16-byte input into 4x4 AES column-major state.
    Args:
        block (bytearray): 16-byte input.
    Returns:
        bytearray: 4x4 AES column-major state.
    """
    state = bytearray(16)
    for row in range(4):
        for col in range(4):
            state[col * 4 + row] = block[row * 4 + col]
    return state


def state_to_byte(state: bytearray) -> bytearray:
    """
    Convert AES column-major state back to 16-byte output.
    Args:
        state (bytearray): 4x4 AES column-major state.
    Returns:
        bytearray: 16-byte output.
    """
    block = bytearray(16)
    for row in range(4):
        for col in range(4):
            block[row * 4 + col] = state[col * 4 + row]
    return block


def get_sbox_value(num):
    """Get a value from the S-Box"""
    return aes_sbox[num]


def get_sbox_invert(num):
    """Get a value from the inverted S-Box"""
    return aes_rsbox[num]


def rotate(word):
    """
    Rotate the word eight bits to the left ( rotate(1d2c3a4f) = 2c3a4f1d )
    Args:
        word (bytearray): 4-byte word.
    Returns:
        bytearray: Rotated word.
    """
    # c = word[0]
    # for i in range(3):
    #    word[i] = word[i + 1]
    # word[3] = c
    # return word
    return circular_shift_left(word, 1)


def get_rcon_value(num):
    """Get a value from the Rcon table"""
    return aes_Rcon[num]


def core(word, iteration):
    """Key Schedule Core operation"""
    # rotate the 32-bit word 8 bits to the left
    word = rotate(word)

    # apply S-Box substitution on all 4 parts of the 32-bit word
    for i in range(4):
        word[i] = get_sbox_value(word[i])

    # XOR the output of the rcon operation with iteration to the first part (leftmost) only
    word[0] = word[0] ^ get_rcon_value(iteration)

    return word


def expand_key(key, key_size, expanded_key_size):
    """
    Expands an 128,192,256 key into an 176,208,240 bytes key
    Args:
        key (bytearray): The key to expand.
        key_size (int): The size of the key in bytes (16, 24, or 32).
        expanded_key_size (int): The size of the expanded key in bytes (176, 208, or 240).
    Returns:
        bytearray: The expanded key with expanded size.
    """
    expanded_key = bytearray(expanded_key_size)
    current_size = 0
    rcon_iteration = 1
    t = bytearray(4)  # temporary 4-byte variable

    # Set the 16, 24, 32 bytes of the expanded key to the input key
    for i in range(key_size):
        expanded_key[i] = key[i]
    current_size += key_size

    while current_size < expanded_key_size:
        # Assign the previous 4 bytes to the temporary value t
        for i in range(4):
            t[i] = expanded_key[(current_size - 4) + i]

        # Every 16, 24, 32 bytes we apply the core schedule to t and increment rcon_iteration
        if current_size % key_size == 0:
            t = core(t, rcon_iteration)
            rcon_iteration += 1

        # For 256-bit keys, we add an extra sbox to the calculation
        if key_size == SIZE_32 and ((current_size % key_size) == 16):
            for i in range(4):
                t[i] = get_sbox_value(t[i])

        # We XOR t with the four-byte block key_size bytes before the new expanded key
        # This becomes the next four bytes in the expanded key
        for i in range(4):
            expanded_key[current_size] = expanded_key[current_size - key_size] ^ t[i]
            current_size += 1

    return expanded_key


def sub_bytes(state):
    """
    Substitute all the values from the state with the value in the SBox
    using the state value as index for the SBox
    """
    for i in range(16):
        state[i] = get_sbox_value(state[i])
    return state


def shift_rows(state):
    """
    Iterate over the 4 rows and call shift_row() on each.
    Args:  
        state (bytearray): 4x4 AES column-major state.
    Returns:
        bytearray: The state after shifting rows. 
    """
    for i in range(4):
        state = shift_row(state, i)
    return state


def shift_row(state_row, nbr):
    """
    Shift a specific row to the left by nbr bytes.
    Args:
        state_row (bytearray): 4-byte row.
        nbr (int): The row number (0-based).
    """
    for i in range(nbr):
        tmp = state_row[nbr * 4]
        for j in range(3):
            state_row[nbr * 4 + j] = state_row[nbr * 4 + j + 1]
        state_row[nbr * 4 + 3] = tmp
    return state_row


def add_round_key(state, round_key):
    """
    XOR the state with the round key.
    Args: 
        state (bytearray): 16-byte.
        round_key (bytearray): 16-byte.
    Returns:
        bytearray: The state after XOR with round key.
    """
    for i in range(16):
        state[i] ^= round_key[i]
    return state


def galois_multiplication(a, b):
    """Galois multiplication of 8-bit characters a and b"""
    p = 0

    for counter in range(8):
        if (b & 1) != 0:
            p ^= a
        hi_bit_set = (a & 0x80)
        a <<= 1
        if hi_bit_set != 0:
            a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p & 0xFF  # Ensure result is 8 bits


def mix_columns(state):
    """Iterate over the 4 columns and call mix_column() on each"""
    column = bytearray(4)

    # Iterate over the 4 columns
    for i in range(4):
        # Construct one column by iterating over the 4 rows
        for j in range(4):
            column[j] = state[j * 4 + i]

        # Apply the mix_column on one column
        column = mix_column(column)

        # Put the values back into the state
        for j in range(4):
            state[j * 4 + i] = column[j]

    return state


def mix_column(column):
    """Mix a single column"""
    cpy = column.copy()

    column[0] = galois_multiplication(cpy[0], 2) ^ \
                galois_multiplication(cpy[3], 1) ^ \
                galois_multiplication(cpy[2], 1) ^ \
                galois_multiplication(cpy[1], 3)

    column[1] = galois_multiplication(cpy[1], 2) ^ \
                galois_multiplication(cpy[0], 1) ^ \
                galois_multiplication(cpy[3], 1) ^ \
                galois_multiplication(cpy[2], 3)

    column[2] = galois_multiplication(cpy[2], 2) ^ \
                galois_multiplication(cpy[1], 1) ^ \
                galois_multiplication(cpy[0], 1) ^ \
                galois_multiplication(cpy[3], 3)

    column[3] = galois_multiplication(cpy[3], 2) ^ \
                galois_multiplication(cpy[2], 1) ^ \
                galois_multiplication(cpy[1], 1) ^ \
                galois_multiplication(cpy[0], 3)

    return column


def create_round_key(expanded_key, round_key_pointer):
    """Create a round key from the expanded key"""
    round_key = bytearray(16)

    # Iterate over the columns
    for i in range(4):
        # Iterate over the rows
        for j in range(4):
            round_key[i + (j * 4)] = expanded_key[(round_key_pointer * 16) + (i * 4) + j]

    return round_key


def inv_sub_bytes(state):
    """Apply the inverse SubBytes transformation"""
    for i in range(16):
        state[i] = get_sbox_invert(state[i])
    return state


def inv_shift_rows(state):
    """Apply the inverse ShiftRows transformation"""
    for i in range(4):
        state = inv_shift_row(state, i)
    return state


def inv_shift_row(state, nbr):
    """
    Each iteration shifts the row to the right by 1

    state is a 16-byte array representing 4x4 matrix
    nbr is the row number (0-based)
    """
    for i in range(nbr):
        tmp = state[nbr * 4 + 3]
        for j in range(3, 0, -1):
            state[nbr * 4 + j] = state[nbr * 4 + j - 1]
        state[nbr * 4] = tmp
    return state


def inv_mix_columns(state):
    """Apply the inverse MixColumns transformation"""
    column = bytearray(4)

    # Iterate over the 4 columns
    for i in range(4):
        # Construct one column by iterating over the 4 rows
        for j in range(4):
            column[j] = state[j * 4 + i]

        # Apply the inv_mix_column on one column
        column = inv_mix_column(column)

        # Put the values back into the state
        for j in range(4):
            state[j * 4 + i] = column[j]

    return state


def inv_mix_column(column):
    """Mix a single column in the inverse direction"""
    cpy = column.copy()

    column[0] = galois_multiplication(cpy[0], 14) ^ \
                galois_multiplication(cpy[3], 9) ^ \
                galois_multiplication(cpy[2], 13) ^ \
                galois_multiplication(cpy[1], 11)

    column[1] = galois_multiplication(cpy[1], 14) ^ \
                galois_multiplication(cpy[0], 9) ^ \
                galois_multiplication(cpy[3], 13) ^ \
                galois_multiplication(cpy[2], 11)

    column[2] = galois_multiplication(cpy[2], 14) ^ \
                galois_multiplication(cpy[1], 9) ^ \
                galois_multiplication(cpy[0], 13) ^ \
                galois_multiplication(cpy[3], 11)

    column[3] = galois_multiplication(cpy[3], 14) ^ \
                galois_multiplication(cpy[2], 9) ^ \
                galois_multiplication(cpy[1], 13) ^ \
                galois_multiplication(cpy[0], 11)

    return column


def circular_shift_left(key: str, shift: int) -> str:
    """
    Circular shift left the key.
    Args:
        key (str): The key to shift.
        shift (int): The number of shifts.
    Returns:
        str: The shifted key.
    """
    return key[shift:] + key[:shift]