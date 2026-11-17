#include <base.h>
#include <concepts.h>
#include <cstdint>
#include <array>
#include <concepts>

namespace Serpent{
    using Serpent128 = Base::SimmetricEncryption<SPNet<Serpent_Generator128, Serpent_Encryption>>;
    using Serpent192 = Base::SimmetricEncryption<SPNet<Serpent_Generator192, Serpent_Encryption>>;
    using Serpent256 = Base::SimmetricEncryption<SPNet<Serpent_Generator256, Serpent_Encryption>>;



    struct Serpent_Generator_Base{
        constexpr static std::size_t round_key_len = 128;
        constexpr static std::size_t round_keys_count = 33;
        constexpr static std::size_t key_len = 0;
        std::array<std::array<std::uint8_t, round_key_len / 8>, round_keys_count> round_keys;
        std::array<std::array<std::uint8_t, round_key_len / 8>, round_keys_count> generate_round_keys(std::array<std::uint8_t, key_len / 8>& key);
    };

    struct Serpent_Generator128: Serpent_Generator_Base{
        constexpr static std::size_t key_len = 128;
    };
   
    struct Serpent_Generator192: Serpent_Generator_Base{
        constexpr static std::size_t key_len = 192;
    };
    
    struct Serpent_Generator256: Serpent_Generator_Base{
        constexpr static std::size_t key_len = 256;
    };

    struct Serpent_Encryption{
        constexpr static std::size_t input_len = 128;
        constexpr static std::size_t output_len = 128;
        constexpr static std::size_t round_key_len = 128;
        std::array<std::uint8_t, output_len / 8> transform(std::array<std::uint8_t, input_len / 8>& block, std::array<std::uint8_t, round_key_len / 8>& round_key);
    };



    
    
    
    
    
    
    template <class T, class U>
    requires Keys_Generator<T> && encryption<U>
    class SPNet{
        private:
            T generator;
            U cipher;
        
        public:
            const static size_t key_len = T::key_len;
            const static size_t input_len = 2 * U::input_len;
            const static size_t output_len = 2 * U::output_len;
            const static size_t round_key_len =  T::round_key_len;
            const static size_t round_keys_count = T::round_keys_count;
        public:
            SPNet(T _generator = T{}, U _cipher = U{}): generator(_generator), cipher(_cipher){}
            
            void generate_round_keys(const std::array<std::uint8_t, key_len / 8>& key); /*{
                round_keys = generator.generate_round_keys(key);
            } */

            std::array<std::uint8_t, output_len / 8> encrypt(const std::array<std::uint8_t, input_len / 8>& block);
            std::array<std::uint8_t, input_len / 8> decrypt(const std::array<std::uint8_t, output_len / 8>& block);

    }
}