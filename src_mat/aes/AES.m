classdef AES
    properties (Access = private)
        key_size
        rounds
        expanded_key
    end

    methods
        function obj = AES(key)
            key = uint8(key(:).');  % row vector
            obj.key_size = numel(key);

            if ~ismember(obj.key_size, [16 24 32])
                error('key_size must be 16, 24, or 32 bytes.');
            end

            switch obj.key_size
                case 16
                    obj.rounds = 10;
                case 24
                    obj.rounds = 12;
                case 32
                    obj.rounds = 14;
            end

            expanded_key_size = 16 * (obj.rounds + 1);
            obj.expanded_key = aes_helper.expand_key( ...
                key, obj.key_size, expanded_key_size);
        end

        function out = encrypt(obj, input_bytes)

            input_bytes = uint8(input_bytes(:).');
            if numel(input_bytes) ~= 16
                error('Input block must be 16 bytes.');
            end

            state = aes_helper.byte_to_state(input_bytes);

            % Initial round
            state = aes_helper.add_round_key( ...
                state, aes_helper.create_round_key(obj.expanded_key, 0));

            % Main rounds
            for round_idx = 1:(obj.rounds - 1)
                state = aes_helper.sub_bytes(state);
                state = aes_helper.shift_rows(state);
                state = aes_helper.mix_columns(state);
                state = aes_helper.add_round_key( ...
                    state, aes_helper.create_round_key(obj.expanded_key, round_idx));
            end

            % Last round
            state = aes_helper.sub_bytes(state);
            state = aes_helper.shift_rows(state);
            state = aes_helper.add_round_key( ...
                state, aes_helper.create_round_key(obj.expanded_key, obj.rounds));

            out = aes_helper.state_to_byte(state);
        end

        function out = decrypt(obj, input_bytes)

            input_bytes = uint8(input_bytes(:).');
            if numel(input_bytes) ~= 16
                error('Input block must be 16 bytes.');
            end

            state = aes_helper.byte_to_state(input_bytes);

            % Initial round
            state = aes_helper.add_round_key( ...
                state, aes_helper.create_round_key(obj.expanded_key, obj.rounds));

            % First round
            for round_idx = (obj.rounds - 1):-1:1
                state = aes_helper.inv_shift_rows(state);
                state = aes_helper.inv_sub_bytes(state);
                state = aes_helper.add_round_key( ...
                    state, aes_helper.create_round_key(obj.expanded_key, round_idx));
                state = aes_helper.inv_mix_columns(state);
            end

            % Last round
            state = aes_helper.inv_shift_rows(state);
            state = aes_helper.inv_sub_bytes(state);
            state = aes_helper.add_round_key( ...
                state, aes_helper.create_round_key(obj.expanded_key, 0));

            out = aes_helper.state_to_byte(state);
        end
    end
end
