# ============================================================
#  Custom Stream Cipher: Shift-Zig Cipher (Zig-Zag Transposition + Vigenere Shift)
#  Keystream: Derived from a text key (e.g., "CAT")
#  Transposition: Zig-zag rail pattern (depth = 3)
# ============================================================

# Convert key to keystream shift values A=0, B=1, ... Z=25
def generate_keystream(key, length):
    key = key.upper()
    shifts = [(ord(c) - ord('A')) for c in key]  # Convert chars to numbers
    return [shifts[i % len(shifts)] for i in range(length)]  # Repeat until match length

# Generate zig-zag rail pattern (depth = number of rails)
def generate_rails(depth, length):
    pattern = []
    row = 0
    direction = 1  # 1 = moving downward, -1 = moving upward

    for _ in range(length):
        pattern.append(row)

        # Change direction at top or bottom rail
        if row == depth - 1:
            direction = -1
        elif row == 0:
            direction = 1

        row += direction

    return pattern

# Encryption function
def encrypt(plaintext, key, depth=3):
    plaintext = plaintext.upper().replace(" ", "")  # Remove spaces
    length = len(plaintext)

    keystream = generate_keystream(key, length)
    rails = generate_rails(depth, length)

    # Step 1 → Apply substitution shift
    shifted = []
    for i in range(length):
        shift = keystream[i]
        char = plaintext[i]
        encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        shifted.append(encrypted_char)

    # Step 2 → Place into rails (transposition)
    rail_text = ['' for _ in range(depth)]
    for i, row in enumerate(rails):
        rail_text[row] += shifted[i]

    # Step 3 → Concatenate all rails as ciphertext
    ciphertext = ''.join(rail_text)
    return ciphertext

# Decryption function
def decrypt(ciphertext, key, depth=3):
    ciphertext = ciphertext.upper()
    length = len(ciphertext)

    keystream = generate_keystream(key, length)
    rails = generate_rails(depth, length)

    # Count characters per rail
    rail_count = [rails.count(r) for r in range(depth)]

    # Split ciphertext into rails based on counted lengths
    rail_text = []
    index = 0
    for count in rail_count:
        rail_text.append(list(ciphertext[index:index+count]))
        index += count

    # Retrieve shifted characters back in zig-zag order
    shifted = []
    rail_pos = [0] * depth
    for row in rails:
        shifted.append(rail_text[row][rail_pos[row]])
        rail_pos[row] += 1

    # Reverse substitution using keystream
    plaintext = ''
    for i in range(length):
        shift = keystream[i]
        char = shifted[i]
        decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        plaintext += decrypted_char

    return plaintext
    
# ============================================================
#                       DEMO SECTION
# ============================================================

plaintext = "ASSALAMUALAIKUM"
key = "CAT"
depth = 3

cipher = encrypt(plaintext, key, depth)
plain = decrypt(cipher, key, depth)

print("Plaintext  : ", plaintext)
print("Key        : ", key)
print("Depth      : ", depth)
print("Ciphertext : ", cipher)
print("Decrypted  : ", plain)
