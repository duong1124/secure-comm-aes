key = uint8('thisisakey123456');  % 16-byte

message   = input('Enter plaintext: ', 's');
plaintext = uint8(message);

[ciphertext, iv] = encrypt_cbc(plaintext, key);

fprintf('Private key:          %s\n', bytes2hex(key));
fprintf('IV (public):          %s\n', bytes2hex(iv));
fprintf('Ciphertext (public):  %s\n', bytes2hex(ciphertext));

% ---- helper local function ----
function h = bytes2hex(b)
    b = uint8(b(:));
    h = upper(reshape(dec2hex(b), 1, []));   % mỗi byte -> 2 ký tự hex
end
