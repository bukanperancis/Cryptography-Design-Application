import string

# we need to do stg for the assignment. i asssume some codes on encryption and decryption!

# Create encryption and decryption mappings
def create_mappings(substitution_alphabet):
    alphabet = string.ascii_uppercase
    encryption_mapping = {alphabet[i]: substitution_alphabet[i] for i in range(len(alphabet))}
    decryption_mapping = {substitution_alphabet[i]: alphabet[i] for i in range(len(alphabet))}
    return encryption_mapping, decryption_mapping

# Encrypt the plaintext using the substitution alphabet
def encrypt(plaintext, encryption_mapping):
    plaintext = plaintext.upper()
    ciphertext = ''.join(encryption_mapping.get(char, char) for char in plaintext)
    return ciphertext

# Decrypt the ciphertext using the reverse substitution alphabet
def decrypt(ciphertext, decryption_mapping):
    ciphertext = ciphertext.upper()
    decrypted_text = ''.join(decryption_mapping.get(char, char) for char in ciphertext)
    return decrypted_text

# Main function to demonstrate encryption and decryption with user input
def main():
    alphabet = string.ascii_uppercase
    
    # Input the substitution alphabet (key) from the user
    substitution_alphabet = input("Enter the substitution alphabet (key): ").upper()
    if len(substitution_alphabet) != 26 or not all(char in alphabet for char in substitution_alphabet):
        print("Invalid substitution alphabet. Please ensure it contains 26 unique letters.")
        return
    
    # Create encryption and decryption mappings
    encryption_mapping, decryption_mapping = create_mappings(substitution_alphabet)
    
    # Input ciphertext from the user
    plaintext = input("Enter the plaintext: ").upper()
    print("Plaintext:", plaintext)

    # Encrypt the plaintext
    ciphertext = encrypt(plaintext, encryption_mapping)
    print("Ciphertext:", ciphertext)

    # Decrypt the ciphertext
    decrypted_text = decrypt(ciphertext, decryption_mapping)
    print("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
