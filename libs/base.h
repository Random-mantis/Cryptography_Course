#include <cstdint>
#include <concepts>
#include <concepts.h>
#include <cstdlib>
#include <array>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <functional>
#include <type_traits>
#include <random>
#include <string>
#include <thread>
#include <future>
#include <any>
#include <constants.h>

namespace Base{

    using size_t = std::size_t;
    size_t rule_index(size_t index, size_t bytes_len, Constants::BitOrder rule) {
        switch (rule) {
        case Constants::BitOrder::First_bit_start0: return bytes_len - index - 1;
        case Constants::BitOrder::First_bit_start1: return bytes_len - index;
        case Constants::BitOrder::Last_bit_start0: return index;
        case Constants::BitOrder::Last_bit_start1: return index - 1;
        }

    }

    Constants::BitOrder rule = Constants::BitOrder::First_bit_start1;

    bool get_bit(std::uint64_t bytes, const size_t index) {
        return (bytes >> index) & 1ULL;
    }

    void set_bit(std::uint64_t& bytes, const bool bit, const size_t index) {
        const std::uint64_t mask = 1ULL << index;
        if (bit) bytes |= mask;
        else bytes &= ~mask;
    }

template <size_t input_len, size_t output_len>
    std::array<std::uint8_t, output_len> bit_permute(
        const std::array<std::uint8_t, input_len>& value,
        const std::array<std::uint8_t, output_len * 8>& table,
        Constants::BitOrder order = Constants::BitOrder::First_bit_start0)
    {
        std::uint64_t bytes = 0;
        for (size_t i = 0; i < input_len; i++) bytes = (bytes << 8) | value[i];

        std::uint64_t out = 0;

        for (size_t i = 0; i < output_len * 8; i++) {
            const size_t in_shift = rule_index(table[i], input_len * 8, order);

            const size_t out_index =
                (order == Constants::BitOrder::First_bit_start1 ||
                 order == Constants::BitOrder::Last_bit_start1) ? i + 1 : i;
            const size_t out_shift = rule_index(out_index, output_len * 8, order);

            const bool bit = get_bit(bytes, in_shift);
            set_bit(out, bit, out_shift);
        }
        bytes = out;

        std::array<std::uint8_t, output_len> output;
        for (size_t i = output_len; i-- > 0;) {
            output[i] = bytes & 0xFF;
            bytes >>= 8;
        }
        return output;
    }

    template <class T>
    requires Encryptor<T>
    class SimmetricEncryption{
        private:
            std::array<std::uint8_t, T::key_len / 8> key;
        protected:
            Constants::EncryptMode e_mode = Constants::EncryptMode::ECB;
            Constants::PackingMode p_mode = Constants::PackingMode::ZEROS;
            std::array<std::uint8_t, T::input_len / 8> initialization{};
            std::vector<std::any> optional_pars{};
            std::vector<std::uint8_t> random_deltas{}; // Только для CTR::RandomDelta.
            T cipher;


        public:
            static constexpr size_t key_len = T::key_len;
            static constexpr size_t input_len = T::input_len;
            static constexpr size_t output_len = T::output_len;
        public:
            template<class Key, typename... Args>
            requires std::same_as<std::decay_t<Key>, std::array<std::uint8_t, key_len / 8>>
            SimmetricEncryption(Key&& _key,
            Constants::EncryptMode _e_mode, 
            Constants::PackingMode _p_mode,
            std::array<std::uint8_t, input_len / 8> _init = {},
            Args&&... args): key(std::forward<Key>(_key)), e_mode(_e_mode), p_mode(_p_mode), initialization(_init) {
                optional_pars.reserve(sizeof...(Args));
                (optional_pars.push_back(std::any(std::forward<Args>(args))), ...);
                set_round_keys(key);
            }

            void set_round_keys(std::array<std::uint8_t, key_len / 8>& key){
                cipher.generate_round_keys(key);
            }

            std::future<void> encryptor(const std::vector<std::uint8_t>& input, std::vector<std::uint8_t>& result){
                return std::async(std::launch::async, &SimmetricEncryption::async_encrypt, this, std::ref(input), std::ref(result));
            }

            std::future<void> decryptor(const std::vector<std::uint8_t>& input, std::vector<std::uint8_t>& result) {
                return std::async(std::launch::async, &SimmetricEncryption::async_decrypt, this, std::ref(input), std::ref(result));
            }

            std::future<void> encryptor(const std::string& input_path, const std::string& output_path){
                return encryptor(std::filesystem::path(input_path), std::filesystem::path(output_path));   
            }

            std::future<void> decryptor(const std::string& input_path, const std::string& output_path){
                return decryptor(std::filesystem::path(input_path), std::filesystem::path(output_path));   
            } 

            std::future<void> encryptor(const std::filesystem::path& input_path, const std::filesystem::path& output_path){
                return std::async(std::launch::async, [this, input_path, output_path]{
                    std::ifstream in(input_path, std::ios::binary);
                    if (!in) throw std::runtime_error("Cannot open input file");
                    std::vector<std::uint8_t> input((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                    std::vector<std::uint8_t> result;
                    async_encrypt(input, result);
                    std::ofstream out(output_path, std::ios::binary);
                    if (!out) throw std::runtime_error("Cannot open output file");
                    out.write(reinterpret_cast<const char*>(result.data()), static_cast<std::streamsize>(result.size()));
                });
            }

            std::future<void> decryptor(const std::filesystem::path& input_path, const std::filesystem::path& output_path){
                return std::async(std::launch::async, [this, input_path, output_path]{
                    std::ifstream in(input_path, std::ios::binary);
                    if (!in) throw std::runtime_error("Cannot open input file");
                    std::vector<std::uint8_t> input((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                    std::vector<std::uint8_t> result;
                    async_decrypt(input, result);
                    std::ofstream out(output_path, std::ios::binary);
                    if (!out) throw std::runtime_error("Cannot open output file");
                    out.write(reinterpret_cast<const char*>(result.data()), static_cast<std::streamsize>(result.size()));
                });
            }

            size_t workers_count() const {
                auto n = std::thread::hardware_concurrency();
                return n == 0 ? size_t{1} : static_cast<size_t>(n);
            }

            void encrypt_writing(std::array<std::uint8_t, input_len / 8>& block, std::vector<std::array<std::uint8_t, output_len / 8>>& result, size_t start_index){
                result[start_index] = cipher.encrypt(block);
            }

            void decrypt_writing(std::array<std::uint8_t, input_len / 8>& block, std::vector<std::array<std::uint8_t, output_len / 8>>& result, size_t start_index){
                result[start_index] = cipher.decrypt(block);
            }

            void cbc_xor_writing(std::array<std::uint8_t, output_len / 8>& decrypted, std::array<std::uint8_t, input_len / 8>& prev, std::vector<std::array<std::uint8_t, output_len / 8>>& result, size_t index){
                result[index] = Xor(decrypted, prev);
            }

            std::vector<std::array<std::uint8_t, output_len / 8>> Encrypt(std::vector<std::array<std::uint8_t, input_len / 8>>& blocks, Constants::EncryptMode mode, std::array<std::uint8_t, input_len / 8>& initialization, std::vector<std::any>& optional_pars){
                std::vector<std::array<std::uint8_t, output_len / 8>> result(blocks.size());
                switch(mode){
                    case Constants::EncryptMode::CBC: {
                        auto C = initialization;
                        for (size_t i = 0; i < blocks.size(); i++){
                            auto X = Xor(blocks[i], C);
                            C = cipher.encrypt(X);
                            result[i] = C;
                        }
                        return result;
                    }
                    case Constants::EncryptMode::PCBC: {
                        auto C = cipher.encrypt(Xor(blocks[0], initialization));
                        result[0] = C;
                        for (size_t i = 1; i < blocks.size(); i++){
                            auto X = Xor(blocks[i], Xor(blocks[i - 1], result[i - 1]));
                            C = cipher.encrypt(X);
                            result[i] = C;
                        }
                        return result;
                    }
                    case Constants::EncryptMode::CFB: {
                        const size_t shift = std::any_cast<size_t>(optional_pars[0]);
                        if (shift == 0 || shift > input_len || shift > output_len) throw std::invalid_argument("CFB segment size is invalid");
                        auto R = initialization;
                        const size_t total_bits = blocks.size() * input_len;
                        for (size_t bit = 0; bit < total_bits; bit += shift) {
                            auto S = cipher.encrypt(R);
                            const size_t take = std::min(shift, total_bits - bit);
                            std::array<std::uint8_t, output_len / 8> segment{};
                            for (size_t b = 0; b < take; b++) {
                                const size_t src = bit + b;
                                const size_t block_i = src / input_len;
                                const size_t bit_in_block = src % input_len;
                                const size_t byte_i = bit_in_block / 8;
                                const std::uint8_t mask = std::uint8_t(1) << (7 - bit_in_block % 8);
                                const std::uint8_t p = (blocks[block_i][byte_i] & mask) ? 1 : 0;
                                const std::uint8_t k = (S[b / 8] & (std::uint8_t(1) << (7 - b % 8))) ? 1 : 0;
                                const std::uint8_t c = p ^ k;
                                if (c) result[block_i][byte_i] |= mask;
                                else result[block_i][byte_i] &= std::uint8_t(~mask);
                                if (c) segment[b / 8] |= std::uint8_t(1) << (7 - b % 8);
                            }
                            R = CFB_update(R, segment, take);
                        }
                        return result;
                    }
                    case Constants::EncryptMode::OFB: {
                        auto O = initialization;
                        for (size_t i = 0; i < blocks.size(); i++){
                            O = cipher.encrypt(O);
                            result[i] = Xor(blocks[i], O);
                        }
                        return result;
                    }
                    case Constants::EncryptMode::CTR:
                    case Constants::EncryptMode::RandomDelta: {
                        std::vector<std::uint8_t> Nonce = std::any_cast<std::vector<std::uint8_t>>(optional_pars[0]);
                        std::vector<std::uint8_t> Counter = std::any_cast<std::vector<std::uint8_t>>(optional_pars[1]);
                        if (Nonce.size() + Counter.size() != input_len / 8) throw std::invalid_argument("Nonce and Counter size is not equal to block size");
                        std::array<std::uint8_t, input_len / 8> NC{};
                        std::copy(Nonce.begin(), Nonce.end(), NC.begin());
                        std::copy(Counter.begin(), Counter.end(), NC.begin() + Nonce.size());
                        std::vector<std::array<std::uint8_t, input_len / 8>> NC_blocks(blocks.size());
                        if (mode == Constants::EncryptMode::RandomDelta) random_deltas.clear();

                        for (size_t i = 0; i < blocks.size(); i++){
                            NC_blocks[i] = NC;
                            const size_t delta = mode == Constants::EncryptMode::CTR ? size_t{1} : static_cast<size_t>(std::rand() % 256);
                            if (mode == Constants::EncryptMode::RandomDelta) random_deltas.push_back(delta);
                            CFT_add(Counter, delta);
                            std::copy(Counter.begin(), Counter.end(), NC.begin() + Nonce.size());
                        }

                        const size_t workers = workers_count();
                        if (blocks.size() <= workers){
                            std::vector<std::thread> threads(blocks.size());
                            for (size_t i = 0; i < blocks.size(); i++) threads[i] = std::thread(&SimmetricEncryption::CFT_writing, this, std::ref(blocks[i]), std::ref(NC_blocks[i]), std::ref(result), i);
                            for (size_t i = 0; i < blocks.size(); i++) threads[i].join();
                        }else{
                            std::vector<std::thread> threads(workers);
                            const size_t batches = blocks.size() / workers;
                            for (size_t i = 0; i < batches; i++){
                                for (size_t j = 0; j < workers; j++) threads[j] = std::thread(&SimmetricEncryption::CFT_writing, this, std::ref(blocks[i * workers + j]), std::ref(NC_blocks[i * workers + j]), std::ref(result), i * workers + j);
                                for (size_t j = 0; j < workers; j++) threads[j].join();
                            }
                            const size_t done = batches * workers;
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j] = std::thread(&SimmetricEncryption::CFT_writing, this, std::ref(blocks[done + j]), std::ref(NC_blocks[done + j]), std::ref(result), done + j);
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j].join();
                        }
                        return result;
                    }
                    default:
                        throw std::invalid_argument("Encrypt mode is not supported");
                }
            }

            std::vector<std::array<std::uint8_t, output_len / 8>> Decrypt(std::vector<std::array<std::uint8_t, input_len / 8>>& blocks, Constants::EncryptMode mode, std::array<std::uint8_t, input_len / 8>& initialization, std::vector<std::any>& optional_pars){
                std::vector<std::array<std::uint8_t, output_len / 8>> result(blocks.size());
                const size_t workers = workers_count();
                switch(mode){
                    case Constants::EncryptMode::ECB: {
                        if (blocks.size() <= workers){
                            std::vector<std::thread> threads(blocks.size());
                            for (size_t i = 0; i < blocks.size(); i++) threads[i] = std::thread(&SimmetricEncryption::decrypt_writing, this, std::ref(blocks[i]), std::ref(result), i);
                            for (size_t i = 0; i < blocks.size(); i++) threads[i].join();
                        }else{
                            std::vector<std::thread> threads(workers);
                            const size_t batches = blocks.size() / workers;
                            for (size_t i = 0; i < batches; i++){
                                for (size_t j = 0; j < workers; j++) threads[j] = std::thread(&SimmetricEncryption::decrypt_writing, this, std::ref(blocks[i * workers + j]), std::ref(result), i * workers + j);
                                for (size_t j = 0; j < workers; j++) threads[j].join();
                            }
                            const size_t done = batches * workers;
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j] = std::thread(&SimmetricEncryption::decrypt_writing, this, std::ref(blocks[done + j]), std::ref(result), done + j);
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j].join();
                        }
                        return result;
                    }
                    case Constants::EncryptMode::CBC: {
                        std::vector<std::array<std::uint8_t, output_len / 8>> decrypted(blocks.size());
                        if (blocks.size() <= workers){
                            std::vector<std::thread> threads(blocks.size());
                            for (size_t i = 0; i < blocks.size(); i++) threads[i] = std::thread(&SimmetricEncryption::decrypt_writing, this, std::ref(blocks[i]), std::ref(decrypted), i);
                            for (size_t i = 0; i < blocks.size(); i++) threads[i].join();
                        }else{
                            std::vector<std::thread> threads(workers);
                            const size_t batches = blocks.size() / workers;
                            for (size_t i = 0; i < batches; i++){
                                for (size_t j = 0; j < workers; j++) threads[j] = std::thread(&SimmetricEncryption::decrypt_writing, this, std::ref(blocks[i * workers + j]), std::ref(decrypted), i * workers + j);
                                for (size_t j = 0; j < workers; j++) threads[j].join();
                            }
                            const size_t done = batches * workers;
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j] = std::thread(&SimmetricEncryption::decrypt_writing, this, std::ref(blocks[done + j]), std::ref(decrypted), done + j);
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j].join();
                        }
                        result[0] = Xor(decrypted[0], initialization);
                        if (blocks.size() > 1){
                            if (blocks.size() - 1 <= workers){
                                std::vector<std::thread> threads(blocks.size() - 1);
                                for (size_t i = 1; i < blocks.size(); i++) threads[i - 1] = std::thread(&SimmetricEncryption::cbc_xor_writing, this, std::ref(decrypted[i]), std::ref(blocks[i - 1]), std::ref(result), i);
                                for (size_t i = 0; i < blocks.size() - 1; i++) threads[i].join();
                            }else{
                                std::vector<std::thread> threads(workers);
                                const size_t total = blocks.size() - 1;
                                const size_t batches = total / workers;
                                for (size_t i = 0; i < batches; i++){
                                    for (size_t j = 0; j < workers; j++){
                                        const size_t idx = i * workers + j + 1;
                                        threads[j] = std::thread(&SimmetricEncryption::cbc_xor_writing, this, std::ref(decrypted[idx]), std::ref(blocks[idx - 1]), std::ref(result), idx);
                                    }
                                    for (size_t j = 0; j < workers; j++) threads[j].join();
                                }
                                const size_t done = batches * workers;
                                for (size_t j = 0; j < total - done; j++){
                                    const size_t idx = done + j + 1;
                                    threads[j] = std::thread(&SimmetricEncryption::cbc_xor_writing, this, std::ref(decrypted[idx]), std::ref(blocks[idx - 1]), std::ref(result), idx);
                                }
                                for (size_t j = 0; j < total - done; j++) threads[j].join();
                            }
                        }
                        return result;
                    }
                    case Constants::EncryptMode::PCBC: {
                        if (blocks.empty()) return result;
                        auto prev_plain = Xor(cipher.decrypt(blocks[0]), initialization);
                        result[0] = prev_plain;
                        auto prev_cipher = blocks[0];
                        for (size_t i = 1; i < blocks.size(); i++){
                            auto plain = Xor(cipher.decrypt(blocks[i]), Xor(prev_plain, prev_cipher));
                            result[i] = plain;
                            prev_plain = plain;
                            prev_cipher = blocks[i];
                        }
                        return result;
                    }
                    case Constants::EncryptMode::CFB: {
                        const size_t shift = std::any_cast<size_t>(optional_pars[0]);
                        if (shift == 0 || shift > input_len || shift > output_len) throw std::invalid_argument("CFB segment size is invalid");
                        auto R = initialization;
                        const size_t total_bits = blocks.size() * input_len;
                        for (size_t bit = 0; bit < total_bits; bit += shift) {
                            auto S = cipher.encrypt(R);
                            const size_t take = std::min(shift, total_bits - bit);
                            std::array<std::uint8_t, output_len / 8> segment{};
                            for (size_t b = 0; b < take; b++) {
                                const size_t src = bit + b;
                                const size_t block_i = src / input_len;
                                const size_t bit_in_block = src % input_len;
                                const size_t byte_i = bit_in_block / 8;
                                const std::uint8_t mask = std::uint8_t(1) << (7 - bit_in_block % 8);
                                const std::uint8_t c = (blocks[block_i][byte_i] & mask) ? 1 : 0;
                                const std::uint8_t k = (S[b / 8] & (std::uint8_t(1) << (7 - b % 8))) ? 1 : 0;
                                const std::uint8_t p = c ^ k;
                                if (p) result[block_i][byte_i] |= mask;
                                else result[block_i][byte_i] &= std::uint8_t(~mask);
                                if (c) segment[b / 8] |= std::uint8_t(1) << (7 - b % 8);
                            }
                            R = CFB_update(R, segment, take);
                        }
                        return result;
                    }
                    case Constants::EncryptMode::OFB:
                        return Encrypt(blocks, mode, initialization, optional_pars);
                    case Constants::EncryptMode::CTR: {
                        return Encrypt(blocks, mode, initialization, optional_pars);
                    }
                    case Constants::EncryptMode::RandomDelta: {
                        if (optional_pars.size() == 3 && std::any_cast<std::vector<std::uint8_t>*>(optional_pars[2]) != nullptr){
                            random_deltas = std::any_cast<std::vector<std::uint8_t>>(optional_pars[2]);
                        }

                        if (random_deltas.size() != blocks.size()) throw std::invalid_argument("Random Delta sequence is not available for decryption");
                        std::vector<std::uint8_t> Nonce = std::any_cast<std::vector<std::uint8_t>>(optional_pars[0]);
                        std::vector<std::uint8_t> Counter = std::any_cast<std::vector<std::uint8_t>>(optional_pars[1]);
                        if (Nonce.size() + Counter.size() != input_len / 8) throw std::invalid_argument("Nonce and Counter size is not equal to block size");
                        std::array<std::uint8_t, input_len / 8> NC{};
                        std::copy(Nonce.begin(), Nonce.end(), NC.begin());
                        std::copy(Counter.begin(), Counter.end(), NC.begin() + Nonce.size());
                        std::vector<std::array<std::uint8_t, input_len / 8>> NC_blocks(blocks.size());
                        for (size_t i = 0; i < blocks.size(); i++){
                            NC_blocks[i] = NC;
                            CFT_add(Counter, random_deltas[i]);
                            std::copy(Counter.begin(), Counter.end(), NC.begin() + Nonce.size());
                        }
                        if (blocks.size() <= workers){
                            std::vector<std::thread> threads(blocks.size());
                            for (size_t i = 0; i < blocks.size(); i++) threads[i] = std::thread(&SimmetricEncryption::CFT_writing, this, std::ref(blocks[i]), std::ref(NC_blocks[i]), std::ref(result), i);
                            for (size_t i = 0; i < blocks.size(); i++) threads[i].join();
                        }else{
                            std::vector<std::thread> threads(workers);
                            const size_t batches = blocks.size() / workers;
                            for (size_t i = 0; i < batches; i++){
                                for (size_t j = 0; j < workers; j++) threads[j] = std::thread(&SimmetricEncryption::CFT_writing, this, std::ref(blocks[i * workers + j]), std::ref(NC_blocks[i * workers + j]), std::ref(result), i * workers + j);
                                for (size_t j = 0; j < workers; j++) threads[j].join();
                            }
                            const size_t done = batches * workers;
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j] = std::thread(&SimmetricEncryption::CFT_writing, this, std::ref(blocks[done + j]), std::ref(NC_blocks[done + j]), std::ref(result), done + j);
                            for (size_t j = 0; j < blocks.size() - done; j++) threads[j].join();
                        }
                        return result;
                    }
                    default:
                        throw std::invalid_argument("Decrypt mode is not supported");
                }
            }

            bool needs_packing() const {
                return e_mode != Constants::EncryptMode::CFB && e_mode != Constants::EncryptMode::OFB && e_mode != Constants::EncryptMode::CTR && e_mode != Constants::EncryptMode::RandomDelta;
            }

            void async_encrypt(const std::vector<std::uint8_t>& input, std::vector<std::uint8_t>& result){
                constexpr size_t block_bytes = input_len / 8;
                std::vector<std::array<std::uint8_t, input_len / 8>> blocks;
                const size_t full = input.size() / block_bytes;
                const size_t rem = input.size() % block_bytes;
                blocks.reserve(full + 1);

                for (size_t i = 0; i < full; i++){
                    std::array<std::uint8_t, input_len / 8> block{};
                    std::copy_n(input.begin() + i * block_bytes, block_bytes, block.begin());
                    blocks.push_back(block);
                }

                if (rem != 0){
                    std::array<std::uint8_t, input_len / 8> block{};
                    std::copy_n(input.begin() + full * block_bytes, rem, block.begin());
                    Packing(block, rem, p_mode);
                    blocks.push_back(block);
                }else if (needs_packing()){
                    std::array<std::uint8_t, input_len / 8> padding_block{};
                    Packing(padding_block, 0, p_mode);
                    blocks.push_back(padding_block);
                }

                std::vector<std::array<std::uint8_t, output_len / 8>> cipher_result(blocks.size());
                const size_t workers = workers_count();
                if (blocks.size() <= workers && e_mode == Constants::EncryptMode::ECB){
                    std::vector<std::thread> threads(blocks.size());
                    for (size_t i = 0; i < blocks.size(); i++) threads[i] = std::thread(&SimmetricEncryption::encrypt_writing, this, std::ref(blocks[i]), std::ref(cipher_result), i);
                    for (size_t i = 0; i < blocks.size(); i++) threads[i].join();
                }else if (e_mode == Constants::EncryptMode::ECB){
                    std::vector<std::thread> threads(workers);
                    const size_t batches = blocks.size() / workers;
                    for (size_t i = 0; i < batches; i++){
                        for (size_t j = 0; j < workers; j++) threads[j] = std::thread(&SimmetricEncryption::encrypt_writing, this, std::ref(blocks[i * workers + j]), std::ref(cipher_result), i * workers + j);
                        for (size_t j = 0; j < workers; j++) threads[j].join();
                    }
                    const size_t done = batches * workers;
                    for (size_t j = 0; j < blocks.size() - done; j++) threads[j] = std::thread(&SimmetricEncryption::encrypt_writing, this, std::ref(blocks[done + j]), std::ref(cipher_result), done + j);
                    for (size_t j = 0; j < blocks.size() - done; j++) threads[j].join();
                }else{
                    cipher_result = Encrypt(blocks, e_mode, initialization, optional_pars);
                }

                result.resize(blocks.size() * block_bytes);

                if (blocks.size() <= workers){
                    std::vector<std::thread> writers(blocks.size());
                    for (size_t i = 0; i < blocks.size(); i++) writers[i] = std::thread(&SimmetricEncryption::result_writing, this, std::ref(cipher_result[i]), std::ref(result), i * block_bytes);
                    for (size_t i = 0; i < blocks.size(); i++) writers[i].join();
                }else{
                    std::vector<std::thread> writers(workers);
                    const size_t batches = blocks.size() / workers;
                    for (size_t i = 0; i < batches; i++){
                        for (size_t j = 0; j < workers; j++) writers[j] = std::thread(&SimmetricEncryption::result_writing, this, std::ref(cipher_result[i * workers + j]), std::ref(result), (i * workers + j) * block_bytes);
                        for (size_t j = 0; j < workers; j++) writers[j].join();
                    }
                    const size_t done = batches * workers;
                    for (size_t j = 0; j < blocks.size() - done; j++) writers[j] = std::thread(&SimmetricEncryption::result_writing, this, std::ref(cipher_result[done + j]), std::ref(result), (done + j) * block_bytes);
                    for (size_t j = 0; j < blocks.size() - done; j++) writers[j].join();
                }
                if (!needs_packing()) result.resize(input.size());
            }

            void async_decrypt(const std::vector<std::uint8_t>& input, std::vector<std::uint8_t>& result){
                constexpr size_t block_bytes = input_len / 8;
                if (input.empty()){
                    result.clear();
                    return;
                }
                if (needs_packing() && input.size() % block_bytes != 0) throw std::invalid_argument("Ciphertext size is not a multiple of block size");

                const size_t block_count = (input.size() + block_bytes - 1) / block_bytes;
                std::vector<std::array<std::uint8_t, input_len / 8>> blocks(block_count);
                for (size_t i = 0; i < block_count; i++){
                    const size_t offset = i * block_bytes;
                    const size_t take = std::min(block_bytes, input.size() - offset);
                    std::copy_n(input.begin() + offset, take, blocks[i].begin());
                }

                std::vector<std::array<std::uint8_t, output_len / 8>> plain_blocks = Decrypt(blocks, e_mode, initialization, optional_pars);
                const size_t workers = workers_count();
                result.resize(plain_blocks.size() * block_bytes);

                if (plain_blocks.size() <= workers){
                    std::vector<std::thread> writers(plain_blocks.size());
                    for (size_t i = 0; i < plain_blocks.size(); i++) writers[i] = std::thread(&SimmetricEncryption::result_writing, this, std::ref(plain_blocks[i]), std::ref(result), i * block_bytes);
                    for (size_t i = 0; i < plain_blocks.size(); i++) writers[i].join();
                }else{
                    std::vector<std::thread> writers(workers);
                    const size_t batches = plain_blocks.size() / workers;
                    for (size_t i = 0; i < batches; i++){
                        for (size_t j = 0; j < workers; j++) writers[j] = std::thread(&SimmetricEncryption::result_writing, this, std::ref(plain_blocks[i * workers + j]), std::ref(result), (i * workers + j) * block_bytes);
                        for (size_t j = 0; j < workers; j++) writers[j].join();
                    }
                    const size_t done = batches * workers;
                    for (size_t j = 0; j < plain_blocks.size() - done; j++) writers[j] = std::thread(&SimmetricEncryption::result_writing, this, std::ref(plain_blocks[done + j]), std::ref(result), (done + j) * block_bytes);
                    for (size_t j = 0; j < plain_blocks.size() - done; j++) writers[j].join();
                }

                if (!needs_packing()) result.resize(input.size());
                else Unpacking(result, p_mode);
            }

            void result_writing(std::array<std::uint8_t, output_len / 8>& block, std::vector<std::uint8_t>& result, size_t start_index){
                std::copy(block.begin(), block.end(), result.begin() + start_index);
            }

            void Unpacking(std::vector<std::uint8_t>& data, Constants::PackingMode mode){
                if (e_mode == Constants::EncryptMode::CFB or 
                    e_mode == Constants::EncryptMode::OFB or
                    e_mode == Constants::EncryptMode::CTR or
                    e_mode == Constants::EncryptMode::RandomDelta) return;
                if (data.empty()) return;
                constexpr size_t block_bytes = input_len / 8;
                if (data.size() % block_bytes != 0) throw std::invalid_argument("Padded data size is invalid");
                switch(mode){
                    case Constants::PackingMode::ZEROS: {
                        while (!data.empty() && data.back() == 0) data.pop_back();
                        return;
                    }
                    case Constants::PackingMode::ANSIX923: {
                        const size_t pad = data.back();
                        if (pad == 0 || pad > block_bytes || pad > data.size()) throw std::invalid_argument("ANSI X.923 padding is invalid");
                        for (size_t i = data.size() - pad; i + 1 < data.size(); i++){
                            if (data[i] != 0) throw std::invalid_argument("ANSI X.923 padding is invalid");
                        }
                        data.resize(data.size() - pad);
                        return;
                    }
                    case Constants::PackingMode::PKC7S: {
                        const size_t pad = data.back();
                        if (pad == 0 || pad > block_bytes || pad > data.size()) throw std::invalid_argument("PKCS7 padding is invalid");
                        for (size_t i = data.size() - pad; i < data.size(); i++){
                            if (data[i] != static_cast<std::uint8_t>(pad)) throw std::invalid_argument("PKCS7 padding is invalid");
                        }
                        data.resize(data.size() - pad);
                        return;
                    }
                    case Constants::PackingMode::ISO10126: {
                        const size_t pad = data.back();
                        if (pad == 0 || pad > block_bytes || pad > data.size()) throw std::invalid_argument("ISO 10126 padding is invalid");
                        data.resize(data.size() - pad);
                        return;
                    }
                }
            }

            void Packing(std::array<std::uint8_t, input_len / 8>& block, size_t filled, Constants::PackingMode mode){
                if (e_mode == Constants::EncryptMode::CFB or 
                    e_mode == Constants::EncryptMode::OFB or
                    e_mode == Constants::EncryptMode::CTR or
                    e_mode == Constants::EncryptMode::RandomDelta) return;
                switch(mode){
                    case Constants::PackingMode::ZEROS:
                        std::fill(block.begin() + filled, block.end(), 0);
                        return;
                    case Constants::PackingMode::ANSIX923:
                        std::fill(block.begin() + filled, block.end() - 1, 0);
                        block.back() = static_cast<std::uint8_t>(input_len / 8 - filled);
                        return;
                    case Constants::PackingMode::PKC7S:
                        std::fill(block.begin() + filled, block.end(), static_cast<std::uint8_t>(input_len / 8 - filled));
                        return;
                    case Constants::PackingMode::ISO10126:
                        std::generate(block.begin() + filled, block.end() - 1, [](){ return static_cast<std::uint8_t>(std::rand() % 256); });
                        block.back() = static_cast<std::uint8_t>(input_len / 8 - filled);
                        return;
                }
            }
            
        

            std::array<std::uint8_t, output_len / 8> Xor(const std::array<std::uint8_t, output_len / 8>& block1, const std::array<std::uint8_t, output_len / 8>& block2){
                std::array<std::uint8_t, output_len / 8> result{};
                for (size_t i = 0; i < output_len / 8; i++) result[i] = block1[i] ^ block2[i];
                return result;
            }

            std::array<std::uint8_t, output_len / 8> CFB_update(std::array<std::uint8_t, output_len / 8>& block, std::array<std::uint8_t, output_len / 8>& C, size_t shift){
                std::array<std::uint8_t, output_len / 8> result{};
                for (size_t i = shift; i < output_len; i++) {
                    const std::uint8_t bit = (block[i / 8] >> (7 - (i % 8))) & 1;
                    result[(i - shift) / 8] |= bit << (7 - ((i - shift) % 8));
                }
                for (size_t i = 0; i < shift; i++) {
                    const std::uint8_t bit = (C[i / 8] >> (7 - (i % 8))) & 1;
                    const size_t dst = output_len - shift + i;
                    result[dst / 8] |= bit << (7 - (dst % 8));
                }
                return result;
            }

            std::vector<std::uint8_t> CFT_add(std::vector<std::uint8_t>& counter, size_t diff = 1){
                for (size_t n = counter.size(); n-- > 0 && diff > 0;){
                    const size_t sum = static_cast<size_t>(counter[n]) + (diff % 256);
                    counter[n] = static_cast<std::uint8_t>(sum % 256);
                    diff = diff / 256 + sum / 256;
                }
                if (diff > 0) throw std::overflow_error("Counter overflow");
                return counter;
            }

            void CFT_writing(std::array<std::uint8_t, input_len / 8>& block, std::array<std::uint8_t, input_len / 8>& NC, std::vector<std::array<std::uint8_t, output_len / 8>>& result, size_t index){
                auto encrypt_result = cipher.encrypt(NC);
                result[index] = Xor(block, encrypt_result);
            }
    
        
            


            
    };

    template<class T, class U>
    requires Keys_Generator<T> && encryption<U>
    class FrienelNet{
    private:
        std::array<std::array<std::uint8_t, T::round_key_len / 8>, T::round_keys_count> round_keys;
    protected:
        T generator;
        U cipher;

    public:
        const static size_t key_len = T::key_len;
        const static size_t input_len = 2 * U::input_len;
        const static size_t output_len = 2 * U::output_len;
        const static size_t round_key_len =  T::round_key_len;
        const static size_t round_keys_count = T::round_keys_count;

        FrienelNet(const T& generator_ = T{}, const U& cipher_ = U{}): generator(generator_), cipher(cipher_) {}

        void generate_round_keys(const std::array<std::uint8_t, key_len / 8>& key){
            round_keys = generator.generate_round_keys(key);
        } 

        std::array<std::uint8_t, output_len / 8> encrypt(const std::array<std::uint8_t, input_len / 8>& block){
            std::array<std::uint8_t, input_len / 8> data = block;
            std::array<std::uint8_t, input_len / 16> left;
            std::array<std::uint8_t, input_len / 16> right;
            std::copy(data.begin(), data.begin() + input_len / 16, left.begin());
            std::copy(data.begin() + input_len / 16, data.end(), right.begin());
            for (size_t i = 0; i < round_keys_count; i++){
                auto next = right;
                auto f = cipher.transform(right, round_keys[i]);
                for (size_t j = 0; j < right.size(); j++) right[j] = left[j] ^ f[j];
                left = next;
            }
            std::array<std::uint8_t, output_len / 8> result;
            std::copy(right.begin(), right.end(), result.begin());
            std::copy(left.begin(), left.end(), result.begin() + output_len / 16);
            return result;
        }

        std::array<std::uint8_t, input_len / 8> decrypt(const std::array<std::uint8_t, output_len / 8>& block){
            std::array<std::uint8_t, output_len / 8> data = block;
            std::array<std::uint8_t, output_len / 16> left;
            std::array<std::uint8_t, output_len / 16> right;
            std::copy(data.begin(), data.begin() + data.size() / 2, left.begin());
            std::copy(data.begin() + data.size() / 2, data.end(), right.begin());
            for (size_t i = 0; i < round_keys_count; i++){
                auto next = right;
                auto f = cipher.transform(right, round_keys[round_keys_count - 1 - i]);
                for (size_t j = 0; j < right.size(); j++) right[j] = left[j] ^ f[j];
                left = next;
            }
            std::array<std::uint8_t, input_len / 8> result;
            std::copy(right.begin(), right.end(), result.begin());
            std::copy(left.begin(), left.end(), result.begin() + input_len / 16);
            return result;
        }
    };
}
