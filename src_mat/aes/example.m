% input
input_bytes = uint8('exampleplaintext');
key         = uint8('thisisakey123456');

disp('Plaintext:'); 
disp(char(input_bytes));

aes = AES(key);

% encrypt & decrypt
encrypted_data = aes.encrypt(input_bytes);
disp('Encrypted bytes (hex):');
disp(upper(dec2hex(encrypted_data)).');

decrypted_data = aes.decrypt(encrypted_data);
disp('Decrypted text:');
disp(char(decrypted_data));
