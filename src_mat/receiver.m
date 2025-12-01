key_hex = strtrim(input('Enter key (hex): ', 's'));
iv_hex  = strtrim(input('Enter IV (hex): ', 's'));
ct_hex  = strtrim(input('Enter ciphertext (hex): ', 's'));

try
    key        = hex2bytes(key_hex);
    iv         = hex2bytes(iv_hex);
    ciphertext = hex2bytes(ct_hex);

    plaintext = decrypt_cbc(ciphertext, key, iv);

    fprintf('\nDecrypted text:\n');
    fprintf('%s\n', char(plaintext));
catch ME
    fprintf('\nDecryption failed (wrong key or error).\n%s\n', ME.message);
end

% ---- helper local function ----
function b = hex2bytes(h)
    h = regexprep(h, '\s', '');   % bỏ khoảng trắng nếu có
    if mod(length(h), 2) ~= 0
        error('Hex string length must be even.');
    end
    b = uint8(sscanf(h, '%2x').');  % mỗi 2 ký tự hex -> 1 byte
end
