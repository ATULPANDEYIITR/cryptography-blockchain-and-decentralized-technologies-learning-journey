/*
    Day 20: Plaintext, Ciphertext, Keys, Encryption and Decryption

    Educational C++ demonstration of the conceptual encryption
    and decryption workflow.

    Important:
    This program demonstrates the relationship between plaintext,
    ciphertext, keys, encryption, and decryption. It does NOT
    implement a production cryptographic algorithm.

    Production applications should use established cryptographic
    libraries rather than custom cryptographic implementations.
*/

#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

/*
    Educational XOR transformation.

    XOR is useful for demonstrating the basic idea that a key can
    participate in a transformation, but this is NOT secure
    encryption and must never be used to protect real information.
*/
string xorTransform(const string& input, const string& key)
{
    if (key.empty())
    {
        throw invalid_argument("Key cannot be empty.");
    }

    string output = input;

    for (size_t i = 0; i < input.size(); ++i)
    {
        output[i] = input[i] ^ key[i % key.size()];
    }

    return output;
}

/*
    Convert binary data into hexadecimal text so that the
    educational ciphertext can be displayed safely.
*/
string toHex(const string& data)
{
    ostringstream output;

    for (unsigned char character : data)
    {
        output << hex
               << setw(2)
               << setfill('0')
               << static_cast<int>(character);
    }

    return output.str();
}

/*
    Convert hexadecimal text back into binary data.
*/
string fromHex(const string& hexData)
{
    if (hexData.size() % 2 != 0)
    {
        throw invalid_argument(
            "Hexadecimal ciphertext must contain an even number "
            "of characters."
        );
    }

    string result;

    for (size_t i = 0; i < hexData.size(); i += 2)
    {
        unsigned int value;

        string byteString = hexData.substr(i, 2);

        stringstream stream;
        stream << hex << byteString;
        stream >> value;

        result.push_back(
            static_cast<char>(value)
        );
    }

    return result;
}

void printSeparator()
{
    cout << string(72, '=') << '\n';
}

int main()
{
    try
    {
        const string plaintext =
            "Plaintext is readable information.";

        const string key =
            "DAY20KEY";

        printSeparator();

        cout << "DAY 20 - PLAINTEXT, CIPHERTEXT, KEYS,\n";
        cout << "         ENCRYPTION AND DECRYPTION\n";

        printSeparator();

        cout << "\n1. PLAINTEXT\n";
        cout << "------------------------------------------------------------------------\n";
        cout << plaintext << '\n';

        cout << "\n2. ENCRYPTION KEY\n";
        cout << "------------------------------------------------------------------------\n";
        cout << key << '\n';

        /*
            Educational transformation.

            XOR is reversible:

                plaintext XOR key = ciphertext

                ciphertext XOR key = plaintext

            This property demonstrates the relationship between
            encryption and decryption but does NOT make XOR itself
            a secure encryption system.
        */
        const string binaryCiphertext =
            xorTransform(plaintext, key);

        const string ciphertext =
            toHex(binaryCiphertext);

        cout << "\n3. CIPHERTEXT\n";
        cout << "------------------------------------------------------------------------\n";
        cout << ciphertext << '\n';

        cout << "\n4. DECRYPTION\n";
        cout << "------------------------------------------------------------------------\n";

        const string recoveredBinary =
            fromHex(ciphertext);

        const string recoveredPlaintext =
            xorTransform(recoveredBinary, key);

        cout << recoveredPlaintext << '\n';

        cout << "\n5. VERIFICATION\n";
        cout << "------------------------------------------------------------------------\n";

        if (recoveredPlaintext == plaintext)
        {
            cout << "SUCCESS: decrypted text matches the original plaintext.\n";
        }
        else
        {
            cout << "ERROR: decrypted text does not match the original.\n";
            return 1;
        }

        cout << "\n6. IMPORTANT SECURITY NOTE\n";
        cout << "------------------------------------------------------------------------\n";
        cout << "This XOR implementation is for education only.\n";
        cout << "It is NOT secure cryptography.\n";
        cout << "Real applications should use established cryptographic libraries.\n";

        cout << '\n';
        printSeparator();

        return 0;
    }
    catch (const exception& error)
    {
        cerr << "ERROR: " << error.what() << '\n';
        return 1;
    }
}