#include "stego_common.hpp"
#include <unistd.h>

using namespace std;
using namespace cv;
using namespace Stego;

// LSB Reader Helper
void read_bits_to_bytes(const Mat& img, long& bit_idx, vector<uint8_t>& out, size_t num_bytes) {
    out.resize(num_bytes);
    memset(out.data(), 0, num_bytes);
    for (size_t i = 0; i < num_bytes; ++i) {
        for (int b = 0; b < 8; ++b) {
            int row = bit_idx / (img.cols * 3);
            int col = (bit_idx / 3) % img.cols;
            int chan = bit_idx % 3;
            if (row >= img.rows) throw runtime_error("End of image reached prematurely");
            uint8_t pixel = img.at<Vec3b>(row, col)[chan];
            out[i] |= ((pixel & 1) << (7 - b));
            bit_idx++;
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        cout << "Usage: ./extract <stego_image>" << endl;
        return 1;
    }

    try {
        Mat img = imread(argv[1]);
        if (img.empty()) throw runtime_error("Failed to load image");

        long bit_idx = 0;

        // 1. 讀取 Header
        vector<uint8_t> raw_header;
        read_bits_to_bytes(img, bit_idx, raw_header, sizeof(Header));
        Header* header = reinterpret_cast<Header*>(raw_header.data());

        if (strncmp(header->magic, "STG2", 4) != 0) {
            throw runtime_error("Invalid or unknown stego format (Magic mismatch).");
        }

        cout << "[+] Detected settings:" << endl;
        cout << "    Algo: " << (header->algo == ALGO_AES ? "AES" : "DES");
        cout << " | Mode: " << (int)header->mode << " | Padding: " << (int)header->padding << endl;
        cout << "    Payload Size: " << header->payload_size << " bytes." << endl;

        // 2. 讀取 Body
        vector<uint8_t> xor_val, xored_key, iv, enc_payload, recv_hash;
        read_bits_to_bytes(img, bit_idx, xor_val, header->xor_val_len);
        read_bits_to_bytes(img, bit_idx, xored_key, header->key_len);
        read_bits_to_bytes(img, bit_idx, iv, header->iv_len);
        read_bits_to_bytes(img, bit_idx, enc_payload, header->payload_size);

        int hash_len = (header->hash_type == HASH_SHA256) ? SHA256_DIGEST_LENGTH : 
                       (header->hash_type == HASH_MD5) ? MD5_DIGEST_LENGTH : SHA_DIGEST_LENGTH;
        read_bits_to_bytes(img, bit_idx, recv_hash, hash_len);

        // 3. 驗證 Hash
        vector<uint8_t> data_chk;
        data_chk.insert(data_chk.end(), raw_header.begin(), raw_header.end());
        data_chk.insert(data_chk.end(), xor_val.begin(), xor_val.end());
        data_chk.insert(data_chk.end(), xored_key.begin(), xored_key.end());
        data_chk.insert(data_chk.end(), iv.begin(), iv.end());
        data_chk.insert(data_chk.end(), enc_payload.begin(), enc_payload.end());

        vector<uint8_t> calc_hash = calculate_hash(data_chk, header->hash_type);
        if (memcmp(calc_hash.data(), recv_hash.data(), hash_len) != 0) {
            throw runtime_error("Integrity Check Failed! (Hash Mismatch)");
        }
        cout << "[+] Hash verified." << endl;

        // 4. 解密 Keys
        vector<uint8_t> key = xored_key;
        xor_data(key, xor_val);

        // 5. 解密 Payload
        vector<uint8_t> decrypted = symmetric_crypt(enc_payload, key, iv, false, 
                                                   header->algo, header->mode, header->padding);

        // 6. 處理 Padding：根據 Header 的 original_size 截斷
        if (decrypted.size() > header->original_size) {
            decrypted.resize(header->original_size);
        }

        // 7. 執行動作
        string fname = "output_payload";
        if (header->payload_type == PAYLOAD_EXE) {
             #ifdef _WIN32 
                fname += ".exe"; 
             #else 
                fname += ".bin"; 
             #endif
        } else {
            fname += ".txt";
        }

        if (header->action == ACT_WRITE || header->action == ACT_EXECUTE) {
            ofstream ofs(fname, ios::binary);
            ofs.write((char*)decrypted.data(), decrypted.size());
            ofs.close();
            cout << "[+] Saved to " << fname << endl;

            if (header->action == ACT_EXECUTE) {
                cout << "[*] Executing..." << endl;
                if (header->payload_type == PAYLOAD_CMD) {
                    string cmd(decrypted.begin(), decrypted.end());
                    system(cmd.c_str());
                } else {
                    #ifndef _WIN32
                    string chmod = "chmod +x " + fname;
                    system(chmod.c_str());
                    string run = "./" + fname;
                    #else
                    string run = fname;
                    #endif
                    system(run.c_str());
                }
            }
        }

    } catch (const exception& e) {
        cerr << "[-] Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}