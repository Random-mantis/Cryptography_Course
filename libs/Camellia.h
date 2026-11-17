#include <base.h>
#include <concepts.h>
#include <cstdint>
#include <array>
#include <concepts>

namespace Camellia{

    using Camilla128 = Base::SimmetricEncryption<FrienelNet<Camilla_Generator128, Camilla_Encryption>>;
    using Camilla192 = Base::SimmetricEncryption<FrienelNet<Camilla_Generator192, Camilla_Encryption>>;
    using Camilla256 = Base::SimmetricEncryption<FrienelNet<Camilla_Generator256, Camilla_Encryption>>;

    struct Camilla_generator_base{
        constexpr static std::size_t round_key_len = 64;
        constexpr static std::size_t round_keys_count = 0;
        constexpr static std::size_t key_len = 0;
        std::array<std::array<std::uint8_t, round_key_len / 8>, round_keys_count> round_keys;
        std::array<std::array<std::uint8_t, round_key_len / 8>, round_keys_count> generate_round_keys(std::array<std::uint8_t, key_len / 8>& key);
    };


    struct Camilla_Generator128: Camilla_generator_base{
        constexpr static std::size_t key_len = 128;
        constexpr static std::size_t round_keys_count = 26;
    };

    struct Camilla_Generator192: Camilla_generator_base{
        constexpr static std::size_t key_len = 192;
        constexpr static std::size_t round_keys_count = 34;
    };

    struct Camilla_Generator256: Camilla_generator_base{
        constexpr static std::size_t key_len = 256;
        constexpr static std::size_t round_keys_count = 34;
    };

    struct Camilla_Encryption{
        constexpr static std::size_t input_len = 128;
        constexpr static std::size_t output_len = 128;
        constexpr static std::size_t round_key_len = 64;
        std::array<std::uint8_t, output_len / 8> transform(std::array<std::uint8_t, input_len / 8>& block, std::array<std::uint8_t, round_key_len / 8>& round_key);
    };




}