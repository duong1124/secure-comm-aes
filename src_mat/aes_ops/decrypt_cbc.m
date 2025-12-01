function plaintext = decrypt_cbc(ciphertext, key, iv)
% plaintext = decrypt_cbc(ciphertext, key, iv)
%
% ciphertext: uint8 hoặc hex đã convert
% key:        char / uint8
% iv:         uint8

    key = uint8(key(:).');
    aes_instance = AES(key);
    aes_cbc = AES_CBC(aes_instance);

    plaintext = aes_cbc.decrypt(ciphertext, iv);
end
