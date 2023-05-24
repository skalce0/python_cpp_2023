#include <string>
#include <pybind11/pybind11.h>
#include "./micro-ecc/uECC.h"

using namespace std;

char version[] = "1.0";

const char* getVersion() {
    return version;
}

class Cle {
private:
    string publicKey;
    string privateKey;

    unsigned char hexCharToBin(const char hex) {
        unsigned char result;

        if (hex >= '0' && hex <= '9') {
            result = hex - '0';
        } else if (hex >= 'A' && hex <= 'F') {
            result = hex - 'A' + 10;
        } else if (hex >= 'a' && hex <= 'f') {
            result = hex - 'a' + 10;
        } else {
            return 0;
        }
        return result;
    }

    void hexStringToBin(unsigned char *out, const char *hexPrivate) {
        for (int i = 0; i < 32; i++) {
            out[i] = hexCharToBin(hexPrivate[2 * i]) << 4 | hexCharToBin(hexPrivate[2 * i + 1]);
        }
    }

    void calculatePublicKey(const unsigned char *privateKey, unsigned char *publicKey) {
        const struct uECC_Curve_t *curve = uECC_secp256k1();
        if (!uECC_compute_public_key(privateKey, publicKey, curve)) {
            // Handle error: computing public key failed
        }
    }

    string binToHex(const string& binary) const {
        string hex;
        hex.reserve(binary.size() * 2);
        for (unsigned char c : binary) {
            hex.push_back("0123456789ABCDEF"[c >> 4]);
            hex.push_back("0123456789ABCDEF"[c & 0xF]);
        }
        return hex;
    }

public:
    Cle() {}
    ~Cle() {}

    void initialize(const string& p) {
        privateKey = p;
        unsigned char a[32];
        hexStringToBin(a, privateKey.c_str());
        unsigned char b[64];
        calculatePublicKey(a, b);
        publicKey = string((char*)b, 64);
    }

    string getPrivateKey() const {
        return privateKey;
    }

    string getPublicKey() const {
        return binToHex(publicKey);
    }
};

namespace py = pybind11;

PYBIND11_MODULE(my_component, m) {
    m.doc() = "greeting_object 1.0";
    m.def("getVersion", &getVersion, "a function returning the version");

    py::class_<Cle>(m, "Cle")
        .def(py::init<>())
        .def("initialize", &Cle::initialize)
        .def("getPrivateKey", &Cle::getPrivateKey)
        .def("getPublicKey", &Cle::getPublicKey);
}
