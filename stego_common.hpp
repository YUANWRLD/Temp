#ifndef STEGO_COMMON_HPP
#define STEGO_COMMON_HPP

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <opencv2/opencv.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

namespace Stego {

    // --- Enums ---
    enum Algo       { ALGO_AES = 0, ALGO_DES = 1 };
    enum Mode       { MODE_ECB = 0, MODE_CBC = 1, MODE_CFB = 2, MODE_OFB = 3 };
    enum Padding    { PAD_PKCS7 = 0, PAD_ZERO = 1 };
    enum HashType   { HASH_MD5 = 0, HASH_SHA1 = 1, HASH_SHA256 = 2 };
    enum PayloadType{ PAYLOAD_CMD = 0, PAYLOAD_EXE = 1 };
    enum PayloadAction { ACT_WRITE = 0, ACT_EXECUTE = 1 };

    // --- Header Structure ---
    #pragma pack(push, 1)
    struct Header {
        char magic[4];          // "STG2" (Version 2)
        uint8_t algo;           // AES/DES
        uint8_t mode;           // ECB/CBC/CFB/OFB
        uint8_t padding;        // PKCS7/ZERO
        uint8_t hash_type;      // MD5/SHA...
        uint8_t payload_type;   // CMD/EXE
        uint8_t action;         // WRITE/EXECUTE
        uint32_t payload_size;  // Encrypted payload size
        uint32_t original_size; // Decrypted size (important for removing padding)
        uint8_t xor_val_len;    // Length of XOR key
        uint8_t iv_len;         // IV Length
        uint8_t key_len;        // Symmetric Key Length
    };
    #pragma pack(pop)

    // --- Helper: Get OpenSSL Cipher ---
    const EVP_CIPHER* get_cipher(int algo, int mode) {
        if (algo == ALGO_AES) {
            switch (mode) {
                case MODE_CBC: return EVP_aes_256_cbc();
                case MODE_ECB: return EVP_aes_256_ecb();
                case MODE_CFB: return EVP_aes_256_cfb();
                case MODE_OFB: return EVP_aes_256_ofb();
            }
        } else if (algo == ALGO_DES) {
            switch (mode) {
                case MODE_CBC: return EVP_des_cbc();
                case MODE_ECB: return EVP_des_ecb();
                case MODE_CFB: return EVP_des_cfb();
                case MODE_OFB: return EVP_des_ofb();
            }
        }
        return EVP_aes_256_cbc(); // Default fallback
    }

    // --- Helper: Hash Calculation ---
    std::vector<uint8_t> calculate_hash(const std::vector<uint8_t>& data, int type) {
        std::vector<uint8_t> hash;
        if (type == HASH_SHA256) {
            hash.resize(SHA256_DIGEST_LENGTH);
            SHA256(data.data(), data.size(), hash.data());
        } else if (type == HASH_MD5) {
            hash.resize(MD5_DIGEST_LENGTH);
            MD5(data.data(), data.size(), hash.data());
        } else {
            hash.resize(SHA_DIGEST_LENGTH);
            SHA1(data.data(), data.size(), hash.data());
        }
        return hash;
    }

    // --- Helper: XOR ---
    void xor_data(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        if (key.empty()) return;
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= key[i % key.size()];
        }
    }

    // --- Core: Symmetric Encryption/Decryption ---
    std::vector<uint8_t> symmetric_crypt(const std::vector<uint8_t>& input, 
                                       const std::vector<uint8_t>& key, 
                                       const std::vector<uint8_t>& iv, 
                                       bool encrypt, int algo, int mode, int padding) {
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        const EVP_CIPHER* cipher = get_cipher(algo, mode);
        
        // Setup context
        EVP_CipherInit_ex(ctx, cipher, NULL, key.data(), iv.empty() ? NULL : iv.data(), encrypt ? 1 : 0);
        
        std::vector<uint8_t> data_to_process = input;
        int block_size = EVP_CIPHER_block_size(cipher);

        // Handle Padding Settings
        if (padding == PAD_PKCS7) {
            EVP_CIPHER_CTX_set_padding(ctx, 1); // Enable OpenSSL standard padding
        } else {
            EVP_CIPHER_CTX_set_padding(ctx, 0); // Disable OpenSSL padding
            
            // Manual ZeroPadding for Encryption
            if (encrypt && (input.size() % block_size != 0)) {
                size_t new_size = input.size() + (block_size - (input.size() % block_size));
                data_to_process.resize(new_size, 0); // Fill with zeros
            }
        }

        std::vector<uint8_t> out(data_to_process.size() + block_size * 2);
        int out_len1 = 0, out_len2 = 0;

        if (EVP_CipherUpdate(ctx, out.data(), &out_len1, data_to_process.data(), data_to_process.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_CipherUpdate failed");
        }
        
        if (EVP_CipherFinal_ex(ctx, out.data() + out_len1, &out_len2) != 1) {
             EVP_CIPHER_CTX_free(ctx);
             throw std::runtime_error("EVP_CipherFinal_ex failed (Wrong Key/Padding?)");
        }
        
        EVP_CIPHER_CTX_free(ctx);
        out.resize(out_len1 + out_len2);
        return out;
    }

    // --- LSB Logic (Unchanged from previous version mostly) ---
    void embed_to_image(cv::Mat& img, const std::vector<uint8_t>& data) {
        long total_bits = data.size() * 8;
        long capacity = img.rows * img.cols * img.channels();
        if (total_bits > capacity) throw std::runtime_error("Image too small!");

        long bit_idx = 0;
        for (int i = 0; i < img.rows; ++i) {
            for (int j = 0; j < img.cols; ++j) {
                cv::Vec3b& pixel = img.at<cv::Vec3b>(i, j);
                for (int c = 0; c < 3; ++c) {
                    if (bit_idx < total_bits) {
                        uint8_t byte = data[bit_idx / 8];
                        uint8_t bit = (byte >> (7 - (bit_idx % 8))) & 1;
                        pixel[c] = (pixel[c] & 0xFE) | bit;
                        bit_idx++;
                    } else return;
                }
            }
        }
    }
}
#endif