'''
Created on Apr 2, 2018

@author: Jason Les
'''
# Set bitmask for bitwise operations. SHA256 hash function uses 32 bit words
MASK = (2**32) - 1

# Initialize hash values 
ihv = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

# Set round constants
k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

def mult_512(n): # Returns lowest multiple of n such that mod 512 = 0
    i = 0    
    while(True):
        if (n+i) % 512 == 0:
            return i
        i += 1 

def ror(n, x): #32-bit right rotate of integer n, x times. 
    return ((n >> x) | (n << (32 - x))) & MASK

def pad(W): # Take input string W and return 512-bit padded message in bytes
    l = (len(W) * 8) # Length of message (8-bit ASCII) in bits
    k = mult_512(l + 8 + 64) # Find K in L + 1  + K + 64 % 512 = 0, 
    # Note that 1 is represented as b'10000000' in return below (128.to_bytes) so the extra zero bits are accounted for in this call
    return bytes(W,'ascii') + (128).to_bytes(1, 'big') + ((0).to_bytes(1, 'big') * int(k/8)) + l.to_bytes(8, 'big')  # Message + bit "1" + k zero bits + 64-bit block equal to l 
       
def sha256(M): # Return byte array SHA256 hash of input string M
    pm = pad(M) # 512-bit padded message in bytes format
    hv = list(ihv) # Copy initial values to hashvalue array 
    
    for m in range(0,len(pm),64) : # Iterate through message in 512-bit (64 byte) chunks
        w = [0] * 64 # Initialize 64-entry message schedule array 
        for i, j in zip(range(16), range(0,63,4)) : w[i] = int.from_bytes(pm[(m + j):(m + j + 4)], 'big') # Copy padded message into first 16 words of message schedule array, 32-bit words
       
        # Extend the first 16 words into the remaining 48 words of the message schedule array
        for i in range(16,64) :
            s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK
    
        # Initialize working variables to current hash values
        a, b, c, d, e, f, g, h = hv
    
        # Run compression function
        for i in range(0,64) :
            s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = h + s1 + ch + k[i] + w[i]
            s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = s0 + maj
            
            h = g
            g = f
            f = e
            e = (d + temp1) & MASK
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK
            
        #  Add the compressed chunk to the current hash value
        hv[0] = (hv[0] + a) & MASK
        hv[1] = (hv[1] + b) & MASK
        hv[2] = (hv[2] + c) & MASK
        hv[3] = (hv[3] + d) & MASK
        hv[4] = (hv[4] + e) & MASK
        hv[5] = (hv[5] + f) & MASK
        hv[6] = (hv[6] + g) & MASK
        hv[7] = (hv[7] + h) & MASK
        
    # Produce the final hash value (big-endian)
    return b''.join(i.to_bytes(4, 'big') for i in hv) 

# Print the SHA256 hash of "Hello World" in hexadecimal. 
inp = "Hello World"
print(''.join('{:02x}'.format(i) for i in sha256(inp))) # Display output in hex 
