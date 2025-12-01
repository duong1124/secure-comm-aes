function [ciphertext, iv] = encrypt_cbc(plaintext, key, iv)
% [ciphertext, iv] = encrypt_cbc(plaintext, key, iv)
%
% plaintext: char hoặc uint8
% key:      char hoặc uint8 (16/24/32 bytes)
% iv:       optional uint8(1x16); nếu bỏ trống => random
%
% ciphertext, iv: uint8 row vectors

    if nargin < 3
        iv = [];
    end

    key = uint8(key(:).');
    aes_instance = AES(key);
    aes_cbc = AES_CBC(aes_instance);

    [ciphertext, iv] = aes_cbc.encrypt(plaintext, iv);
end
