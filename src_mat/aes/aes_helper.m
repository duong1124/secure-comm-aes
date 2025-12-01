classdef aes_helper
    % Các hàm trợ giúp cho AES (static methods)

    methods (Static)
        function state = byte_to_state(block)
            % Convert 16-byte linear block (row-major) -> AES state (column-major)
            block = uint8(block(:).');
            if numel(block) ~= 16
                error('Block must be 16 bytes.');
            end
            state = zeros(1,16,'uint8');
            for row = 0:3
                for col = 0:3
                    state(col*4 + row + 1) = block(row*4 + col + 1);
                end
            end
        end

        function block = state_to_byte(state)
            % Convert AES state (column-major) -> 16-byte block (row-major)
            state = uint8(state(:).');
            if numel(state) ~= 16
                error('State must be 16 bytes.');
            end
            block = zeros(1,16,'uint8');
            for row = 0:3
                for col = 0:3
                    block(row*4 + col + 1) = state(col*4 + row + 1);
                end
            end
        end

        function v = get_sbox_value(num)
            v = aes_constant.aes_sbox(double(num) + 1);
        end

        function v = get_sbox_invert(num)
            v = aes_constant.aes_rsbox(double(num) + 1);
        end

        function out = rotate(word)
            % Rotate 4-byte word left 1 byte
            word = uint8(word(:).');
            out = aes_helper.circular_shift_left(word, 1);
        end

        function v = get_rcon_value(num)
            v = aes_constant.aes_Rcon(double(num) + 1);
        end

        function word = core(word, iteration)
            % Key Schedule Core
            word = aes_helper.rotate(word);
            for i = 1:4
                word(i) = aes_helper.get_sbox_value(word(i));
            end
            word(1) = bitxor(word(1), aes_helper.get_rcon_value(iteration));
        end

        function expanded_key = expand_key(key, key_size, expanded_key_size)
            % Expand 128/192/256-bit key thành 176/208/240 byte
            key = uint8(key(:).');
            expanded_key = zeros(1, expanded_key_size, 'uint8');
            current_size = 0;
            rcon_iteration = 1;
            t = zeros(1,4,'uint8');

            % copy key gốc
            expanded_key(1:key_size) = key(1:key_size);
            current_size = key_size;

            while current_size < expanded_key_size
                % lấy 4 byte trước đó
                for i = 1:4
                    t(i) = expanded_key(current_size - 4 + i);
                end

                if mod(current_size, key_size) == 0
                    t = aes_helper.core(t, rcon_iteration);
                    rcon_iteration = rcon_iteration + 1;
                end

                if key_size == aes_constant.SIZE_32 && mod(current_size, key_size) == 16
                    for i = 1:4
                        t(i) = aes_helper.get_sbox_value(t(i));
                    end
                end

                for i = 1:4
                    expanded_key(current_size + 1) = bitxor( ...
                        expanded_key(current_size - key_size + 1), t(i));
                    current_size = current_size + 1;
                end
            end
        end

        function state = sub_bytes(state)
            state = uint8(state(:).');
            for i = 1:16
                state(i) = aes_helper.get_sbox_value(state(i));
            end
        end

        function state = shift_rows(state)
            state = uint8(state(:).');
            for i = 0:3
                state = aes_helper.shift_row(state, i);
            end
        end

        function state = shift_row(state, nbr)
            % Dịch trái một row (nbr = 0..3)
            for k = 1:nbr
                row_start = nbr*4 + 1;
                tmp = state(row_start);
                for j = 0:2
                    state(row_start + j) = state(row_start + j + 1);
                end
                state(row_start + 3) = tmp;
            end
        end

        function state = add_round_key(state, round_key)
            state = bitxor(uint8(state), uint8(round_key));
        end

        function p = galois_multiplication(a, b)
            % Galois multiplication trong GF(2^8)
            a = uint8(a);
            b = uint8(b);
            p = uint8(0);
            for counter = 1:8
                if bitand(b, 1) ~= 0
                    p = bitxor(p, a);
                end
                hi_bit_set = bitand(a, uint8(128)); % 0x80
                a = bitshift(a, 1);
                if hi_bit_set ~= 0
                    a = bitxor(a, uint8(27));       % 0x1b
                end
                b = bitshift(b, -1);
            end
            p = bitand(p, uint8(255));
        end

        function state = mix_columns(state)
            state = uint8(state(:).');
            column = zeros(1,4,'uint8');
            for i = 0:3
                for j = 0:3
                    column(j+1) = state(j*4 + i + 1);
                end
                column = aes_helper.mix_column(column);
                for j = 0:3
                    state(j*4 + i + 1) = column(j+1);
                end
            end
        end

        function column = mix_column(column)
            cpy = uint8(column(:).');
            column = zeros(1,4,'uint8');

            column(1) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(1),2), ...
                aes_helper.galois_multiplication(cpy(4),1)), ...
                bitxor(aes_helper.galois_multiplication(cpy(3),1), ...
                       aes_helper.galois_multiplication(cpy(2),3)));

            column(2) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(2),2), ...
                aes_helper.galois_multiplication(cpy(1),1)), ...
                bitxor(aes_helper.galois_multiplication(cpy(4),1), ...
                       aes_helper.galois_multiplication(cpy(3),3)));

            column(3) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(3),2), ...
                aes_helper.galois_multiplication(cpy(2),1)), ...
                bitxor(aes_helper.galois_multiplication(cpy(1),1), ...
                       aes_helper.galois_multiplication(cpy(4),3)));

            column(4) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(4),2), ...
                aes_helper.galois_multiplication(cpy(3),1)), ...
                bitxor(aes_helper.galois_multiplication(cpy(2),1), ...
                       aes_helper.galois_multiplication(cpy(1),3)));
        end

        function round_key = create_round_key(expanded_key, round_key_pointer)
            expanded_key = uint8(expanded_key(:).');
            round_key = zeros(1,16,'uint8');
            for i = 0:3
                for j = 0:3
                    round_key(i + j*4 + 1) = ...
                        expanded_key(round_key_pointer*16 + i*4 + j + 1);
                end
            end
        end

        function state = inv_sub_bytes(state)
            state = uint8(state(:).');
            for i = 1:16
                state(i) = aes_helper.get_sbox_invert(state(i));
            end
        end

        function state = inv_shift_rows(state)
            state = uint8(state(:).');
            for i = 0:3
                state = aes_helper.inv_shift_row(state, i);
            end
        end

        function state = inv_shift_row(state, nbr)
            % Dịch phải một row (ngược ShiftRows)
            for k = 1:nbr
                row_start = nbr*4 + 1;
                tmp = state(row_start + 3);
                for j = 3:-1:1
                    state(row_start + j) = state(row_start + j - 1);
                end
                state(row_start) = tmp;
            end
        end

        function state = inv_mix_columns(state)
            state = uint8(state(:).');
            column = zeros(1,4,'uint8');
            for i = 0:3
                for j = 0:3
                    column(j+1) = state(j*4 + i + 1);
                end
                column = aes_helper.inv_mix_column(column);
                for j = 0:3
                    state(j*4 + i + 1) = column(j+1);
                end
            end
        end

        function column = inv_mix_column(column)
            cpy = uint8(column(:).');
            column = zeros(1,4,'uint8');

            column(1) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(1),14), ...
                aes_helper.galois_multiplication(cpy(4),9)), ...
                bitxor(aes_helper.galois_multiplication(cpy(3),13), ...
                       aes_helper.galois_multiplication(cpy(2),11)));

            column(2) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(2),14), ...
                aes_helper.galois_multiplication(cpy(1),9)), ...
                bitxor(aes_helper.galois_multiplication(cpy(4),13), ...
                       aes_helper.galois_multiplication(cpy(3),11)));

            column(3) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(3),14), ...
                aes_helper.galois_multiplication(cpy(2),9)), ...
                bitxor(aes_helper.galois_multiplication(cpy(1),13), ...
                       aes_helper.galois_multiplication(cpy(4),11)));

            column(4) = bitxor(bitxor( ...
                aes_helper.galois_multiplication(cpy(4),14), ...
                aes_helper.galois_multiplication(cpy(3),9)), ...
                bitxor(aes_helper.galois_multiplication(cpy(2),13), ...
                       aes_helper.galois_multiplication(cpy(1),11)));
        end

        function out = circular_shift_left(key, shift)
            key = uint8(key(:).');
            n = numel(key);
            shift = mod(shift, n);
            if shift == 0
                out = key;
            else
                out = [key(shift+1:end) key(1:shift)];
            end
        end
    end
end
