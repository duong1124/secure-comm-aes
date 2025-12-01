classdef AES_CBC

    properties
        aes         % (class AES.m)
        block_size = 16;
    end

    methods
        function obj = AES_CBC(aesObj)
            % aesObj: instance AES đã khởi tạo với key
            obj.aes = aesObj;
        end

        function [ciphertext, iv] = encrypt(obj, plaintext, iv)
            % [ciphertext, iv] = encrypt(obj, plaintext, iv)
            %
            % plaintext: uint8 hoặc char (sẽ convert sang uint8)
            % iv (optional): uint8(1x16). Nếu bỏ trống => random iv.
            %
            % ciphertext, iv: uint8 row vectors.

            pt = uint8(plaintext(:).');   % row vector

            if nargin < 3 || isempty(iv)
                % giống os.urandom(16)
                iv = uint8(randi([0 255], 1, obj.block_size));
            else
                iv = uint8(iv(:).');
                if numel(iv) ~= obj.block_size
                    error('IV must be %d bytes', obj.block_size);
                end
            end

            % PKCS#7 padding
            padded = AES_CBC.pkcs7_pad(pt, obj.block_size);

            ciphertext = zeros(1, 0, 'uint8');
            previous_block = iv;

            % xử lý từng block 16 byte
            for i = 1:obj.block_size:numel(padded)
                block = padded(i:i + obj.block_size - 1);
                % XOR với block trước đó (hoặc IV)
                xored_block = AES_CBC.xor_bytes(block, previous_block);
                % mã hóa 1 block AES
                encrypted_block = obj.aes.encrypt(xored_block);
                ciphertext = [ciphertext encrypted_block]; %#ok<AGROW>
                previous_block = encrypted_block;
            end
        end

        function plaintext = decrypt(obj, ciphertext, iv)
            % plaintext = decrypt(obj, ciphertext, iv)
            %
            % ciphertext: uint8 row vector, length multiple of 16
            % iv: uint8(1x16)

            ct = uint8(ciphertext(:).');
            iv = uint8(iv(:).');

            if numel(iv) ~= obj.block_size
                error('IV must be %d bytes', obj.block_size);
            end
            if mod(numel(ct), obj.block_size) ~= 0
                error('Ciphertext length must be multiple of block size');
            end

            previous_block = iv;
            pt = zeros(1, 0, 'uint8');

            for i = 1:obj.block_size:numel(ct)
                block = ct(i:i + obj.block_size - 1);
                % giải mã block AES
                decrypted_block = obj.aes.decrypt(block);
                % XOR với block trước (hoặc IV)
                plain_block = AES_CBC.xor_bytes(decrypted_block, previous_block);
                pt = [pt plain_block]; %#ok<AGROW>
                previous_block = block;
            end

            % bỏ padding PKCS#7
            plaintext = AES_CBC.pkcs7_unpad(pt);
        end
    end

    methods (Static, Access = private)
        function out = pkcs7_pad(data, block_size)
            data = uint8(data(:).');
            pad_len = block_size - mod(numel(data), block_size);
            if pad_len == 0
                pad_len = block_size;
            end
            pad = uint8(repmat(pad_len, 1, pad_len));
            out = [data pad];
        end

        function out = pkcs7_unpad(data)
            data = uint8(data(:).');
            if isempty(data)
                error('Cannot unpad empty data');
            end
            pad_len = double(data(end));
            if pad_len <= 0 || pad_len > numel(data)
                error('Invalid padding');
            end
            if any(data(end-pad_len+1:end) ~= data(end))
                error('Invalid padding');
            end
            out = data(1:end-pad_len);
        end

        function out = xor_bytes(a, b)
            a = uint8(a(:).');
            b = uint8(b(:).');
            if numel(a) ~= numel(b)
                error('xor_bytes: inputs must have the same length');
            end
            out = bitxor(a, b);
        end
    end
end
