import numpy as np

class SPN:
    def __init__(self, plaintext, k, sub_z, perm_z):
        self.plaintext = plaintext
        self.k = k
        self.z = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
        self.sub_z = sub_z
        self.perm_z = perm_z
    
    def convertBinary(self, n):
        k=[]
        while (n > 0):
            a=int(float(n%2))
            k.append(a)
            n=(n-a)/2
        k.append(0)
        string = ""
        for j in k[::-1]:
            string=string+str(j)
        while len(string) < 4:
            string = "0" + string
        if len(string) > 4:
            string = string[1:]
            
        return string
    
    def bitwiseAddition(self, round_key, state):
        XOR = ""
        
        for i in range(0, len(round_key)):
            XOR = XOR + "{}".format((int(state[i]) + int(round_key[i])) % 2)
            
        return XOR
    
    def substitution(self, state, z, sub_z):
        substitution_state = ""
        
        for j in range(0, 4):
            number = 0
            letter = state[j*4:(j*4)+4]
            number = number + int(letter[0])*2**3 + int(letter[1])*2**2 + int(letter[2])*2**1 + int(letter[3])*2**0
            state_sub = z.index(sub_z[number])
            substitution_state = substitution_state + "{}".format(self.convertBinary(state_sub))
            
        return substitution_state
    
    def permutation(self, state, perm_z, plaintext):
        perm = [-1] * len(plaintext)
        perm_state = ""
        for l in range(0, len(state)):
            new_pos = perm_z[l] - 1
            perm[new_pos] = state[l]
            
        for m in range(0, len(perm)):
            perm_state = perm_state + "{}".format(perm[m])
            
        return perm_state
    
    def encryptSPN(self):
        end_state = self.plaintext
        k_start = 0
        
        # apply for k0, k1 and k2
        for key in range(0, 3):
            round_key = self.k[k_start:k_start+16]
        
            # bitwise addition
            XOR = self.bitwiseAddition(round_key, end_state)
            
            #substitution
            sub = self.substitution(XOR, self.z, self.sub_z)
            
            # permutation
            perm = self.permutation(sub, self.perm_z, self.plaintext)
            end_state = perm
            
            k_start += 4
        
        # bitwise addition
        # k3
        round_key = self.k[k_start:k_start+16]
        XOR = self.bitwiseAddition(round_key, perm)
        
        #substitution    
        sub = self.substitution(XOR, self.z, self.sub_z)
        
        # bitwise addition
        # k4    
        round_key = self.k[-16:]
        XOR = self.bitwiseAddition(round_key, sub)
            
        end_state = XOR
        
        return end_state
    
    def decryptSPN(self, ciphertext):
        # calculate inverse S-box
        inv_sub_z = ["-1" for _ in range(0, len(self.sub_z))]
        for i in range(0, len(self.sub_z)):
            new_index = self.z.index(self.sub_z[i])
            inv_sub_z[new_index] = self.z[i]
            
        orig_round_keys = []
        k_start = 0
        for key in range(0, 5):
            orig_round_keys.append(self.k[k_start:k_start+16])
            k_start += 4
        round_keys = []
        round_keys.append(orig_round_keys[4])
        round_keys.append(self.permutation(orig_round_keys[3], self.perm_z, ciphertext))
        round_keys.append(self.permutation(orig_round_keys[2], self.perm_z, ciphertext))
        round_keys.append(self.permutation(orig_round_keys[1], self.perm_z, ciphertext))
        round_keys.append(orig_round_keys[0])
    
        end_state = ciphertext
        
        # apply for k0, k1 and k2
        for key in range(0, 3):
            round_key = round_keys[key]
        
            # bitwise addition
            XOR = self.bitwiseAddition(round_key, end_state)
            
            #substitution
            sub = self.substitution(XOR, self.z, inv_sub_z)
            
            # permutation
            perm = self.permutation(sub, self.perm_z, self.plaintext)
            end_state = perm
            
            k_start += 4
        
        # bitwise addition
        # k3
        round_key = round_keys[3]
        XOR = self.bitwiseAddition(round_key, perm)
        
        #substitution    
        sub = self.substitution(XOR, self.z, inv_sub_z)
        
        # bitwise addition
        # k4    
        round_key = round_keys[4]
        XOR = self.bitwiseAddition(round_key, sub)
            
        end_state = XOR
            
        return XOR

    def diffDistrTable(self):
        occurrences = [[-1 for _ in range(0,17)] for _ in range(0,17)]
        for a_p in range(0, 16):
            a_prime = self.convertBinary(a_p)
            occurrences[a_p+1][0] = a_p
            occurrences[0][a_p+1] = a_p
            table = [[0 for _ in range(0,16)] for _ in range(0,5)]
            for i in range(0,16):
                # a -> z
                table[0][i] = self.convertBinary(i)
                # a_star -> a xor a_prime
                table[1][i] = self.bitwiseAddition(table[0][i], a_prime)
                # b -> sub_z(a)
                table[2][i] = self.convertBinary(self.z.index(self.sub_z[i]))
                # b_star -> sub_z(a_star)
                b_star = int(table[1][i][0])*2**3 + int(table[1][i][1])*2**2 + int(table[1][i][2])*2**1 + int(table[1][i][3])*2**0
                table[3][i] = self.convertBinary(self.z.index(self.sub_z[b_star]))
                # b_prime -> b xor b_star
                table[4][i] = self.bitwiseAddition(table[2][i], table[3][i])

            occurrences_a_p = []
            for i in range(0,16):
                occurrences_a_p.append(table[4].count(table[0][i]))
            occurrences[a_p+1][1:] = occurrences_a_p

        return np.array(occurrences)
    
plaintext = "0100111010100001"

# 5 round keys -> k0, k1, k2, k3 and k4
k = "11100111011001111001000000111101"

sub_z = ["4", "1", "E", "8", "D", "6", "2", "B", "F", "C", "9", "7", "3", "A", "5", "0"]
perm_z = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]

cipher1 = SPN(plaintext, k, sub_z, perm_z)

encryption = cipher1.encryptSPN()
print("Plaintext is {}".format(plaintext))
print("Ciphertext is {}".format(encryption))

decryption = cipher1.decryptSPN(encryption)
print("Plaintext is {}".format(decryption))

sub_z = ["7", "D", "E", "3", "0", "6", "9", "A", "1", "2", "8", "5", "B", "C", "4", "F"]
cipher2 = SPN(plaintext, k, sub_z, perm_z)
diffDistrTab = cipher2.diffDistrTable()
print(diffDistrTab)