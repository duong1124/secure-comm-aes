# Few notations while coverting Python to Matlab

- **File name must match class name**
  - In MATLAB, each class must be defined in a `.m` file with the same name.

- **No `import ...` like Python**
  - MATLAB does not support `from x import y`.
  - Any `.m` file (class or function) in the same folder (or on the MATLAB path via `addpath`) is automatically visible to others.

- **Static methods / helper functions**
  - Python can have many free functions in one file.
  - In MATLAB:
    - For classes: helper code must be inside `methods` / `methods (Static)`.
    - For standalone functions: each function should have its own `.m` file, or be a local function at the end of the file (after the main function `end`).

- **Index starts at 1, not 0**
  - Critical for AES: all state/byte indexing changes.
  - Python:
    ```python
    for i in range(4):
        state[col * 4 + i] = ...
    ```
  - MATLAB:
    ```matlab
    for i = 0:3
        state(col*4 + i + 1) = ...;
    end
    ```

- **Data types**
  - MATLAB uses `uint8`, `char`, `double`, etc. You must convert explicitly.
  - For AES and bitwise operations, keep everything in `uint8` to ensure correct behavior with `bitxor`, `bitand`, `bitshift`, etc.

- **Strings vs arrays**
  - In MATLAB, `'abc'` is a character array (equivalent to `uint8('abc')` in Python).
  - For bitwise operations, always cast to `uint8` instead of working on `char` or `double`.

- **Function structure and `end`**
  - MATLAB functions must end with `end` (for non-inline definitions).
  - You cannot freely `return` in the middle like Python; control flow must be structured inside the function body.

- **Random bytes**
  - Python:
    ```python
    iv = os.urandom(16)
    ```
  - MATLAB:
    ```matlab
    iv = uint8(randi([0 255], 1, 16));
    ```

- **Padding and XOR**
  - Python:
    ```python
    padding = bytes([n] * n)
    ```
  - MATLAB:
    ```matlab
    padding = uint8(repmat(n, 1, n));
    ```
  - Python `xor_bytes(a, b)`:
    ```python
    return bytes(x ^ y for x, y in zip(a, b))
    ```
  - MATLAB:
    ```matlab
    out = bitxor(uint8(a), uint8(b));
    ```

- **Normalize vector shape**
  - MATLAB distinguishes between row `[1xN]` and column `[Nx1]` vectors.
  - Use:
    ```matlab
    v = v(:).';
    ```
    to force a row vector (common for byte arrays in crypto code).
