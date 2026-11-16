#include <concepts>
#include <cstdint>
#include <type_traits>
#include <array>

using size_t = std::size_t;

template <class T>
concept Encryptor = (T::key_len % 8 == 0) && (T::input_len % 8 == 0) && (T::output_len % 8 == 0) && requires(T cipher,
    const std::array<std::uint8_t, T::key_len / 8>& key,
    const std::array<std::uint8_t, T::input_len / 8>& block,
    const std::array<std::uint8_t, T::output_len / 8>& encrypted) {
    cipher.generate_round_keys(key);
    {T::round_keys_count} -> std::convertible_to<size_t>;
    {T::round_key_len} -> std::convertible_to<size_t>;
    { cipher.encrypt(block) } -> std::convertible_to<std::array<std::uint8_t, T::output_len / 8>>;
    { cipher.decrypt(encrypted) } -> std::convertible_to<std::array<std::uint8_t, T::input_len / 8>>;
};


template <class function>
concept Keys_Generator = (function::key_len % 8 == 0) && (function::round_key_len % 8 == 0) && (function::round_keys_count > 0) && requires(function f, const std::array<std::uint8_t, function::key_len / 8>& key) {
    {function::key_len} -> std::convertible_to<size_t>;
    {function::round_key_len} -> std::convertible_to<size_t>;
    {function::round_keys_count} -> std::convertible_to<size_t>;
    {f.generate_round_keys(key) } -> std::convertible_to<std::array<std::array<std::uint8_t, function::round_key_len / 8>, function::round_keys_count>>;
};

template <class function>
concept encryption = (function::input_len % 8 == 0) && (function::round_key_len % 8 == 0) && (function::output_len % 8 == 0) && requires(function f, const std::array<std::uint8_t, function::input_len / 8>& block,
    const std::array<std::uint8_t, function::round_key_len / 8>& round_key) {
    {function::input_len} -> std::convertible_to<size_t>;
    {function::round_key_len} -> std::convertible_to<size_t>;
    {function::output_len} -> std::convertible_to<size_t>;    
    { f.transform(block, round_key) } -> std::convertible_to<std::array<std::uint8_t, function::output_len / 8>>;
};