# global

#    Declaration 
#
# 1. This program is built under the concept 
#    provided by following websites: 
#    DES:  
#    1. http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
#    2. https://crypto.stackexchange.com/questions/9674
#       /how-does-des-decryption-work-is-it-the-same-as-encryption-or-the-reverse
#    3. https://www.vocal.com/cryptography/tdes/
#
#    4. https://www.tutorialspoint.com/cryptography/triple_des.htm

require_relative "EncryptionHeader.rb"
module TripleDES
    class TripleDES_ENCRYPTION
        ##==========================
        ##
        ## key table
        ##
        ##==========================
        @@PC1 =  [
                57,49,41,33,25,17,9,
                 1,58,50,42,34,26,18,
                10, 2,59,51,43,35,27,
                19,11, 3,60,52,44,36,
                63,55,47,39,31,23,15,
                 7,62,54,46,38,30,22,
                14, 6,61,53,45,37,29,
                21,13, 5,28,20,12, 4
                ]
        @@PC2 =  [
                14,17,11,24, 1, 5,
                 3,28,15, 6,21,10,
                23,19,12, 4,26, 8,
                16, 7,27,20,13, 2,
                41,52,31,37,47,55,
                30,40,51,45,33,48,
                44,49,39,56,34,53,
                46,42,50,36,29,32,
                ]
        
        
        @@SHIFTS = [
                    1,1,2,2,2,
                    2,2,2,1,2,
                    2,2,2,2,2,
                    1
                 ]
        
        @@IP =   [
                    58,50,42,34,26,18,10, 2,
                    60,52,44,36,28,20,12, 4,
                    62,54,46,38,30,22,14, 6,
                    64,56,48,40,32,24,16, 8,
                    57,49,41,33,25,17, 9, 1,
                    59,51,43,35,27,19,11, 3,
                    61,53,45,37,29,21,13, 5,
                    63,55,47,39,31,23,15, 7
                ]
        
        @@BIT_SELECTION =    [
                                32, 1, 2, 3, 4, 5,
                                 4, 5, 6, 7, 8, 9,
                                 8, 9,10,11,12,13,
                                12,13,14,15,16,17,
                                16,17,18,19,20,21,
                                20,21,22,23,24,25,
                                24,25,26,27,28,29,
                                28,29,30,31,32, 1
                            ]
                            
        @@S1 =   [
                    14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 8, 0, 7,
                     0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
                     4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
                    15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13
                ]
        
        @@S2 =   [
                    15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
                     3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
                     0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
                    13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9
                ]
        
        @@S3 =   [
                    10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
                    13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
                    13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
                     1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12
                ]
                
        @@S4 =   [
                     7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4, 15,
                    13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14,  9,
                    10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8,  4,
                     3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2, 14
                ]
        
        @@S5 =   [
                     2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
                    14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
                     4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
                    11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3
                ]
        
        @@S6 =   [
                    12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
                    10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
                     9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
                     4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,
                ]
        
        @@S7 =   [
                     4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
                    13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
                     1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
                     6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12, 
                ]
        
        @@S8 =   [
                    13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
                     1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
                     7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
                     2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6, 11
                ]
        
        @@P =    [
                    16, 7,20,21,
                    29,12,28,17,
                     1,15,23,26,
                     5,18,31,10,
                     2, 8,24,14,
                    32,27, 3, 9,
                    19,13,30, 6,
                    22,11, 4,25
                ]
        
        @@IP_1 = [
                    40, 8,48,16,56,24,64,32,
                    39, 7,47,15,55,23,63,31,
                    38, 6,46,14,54,22,62,30,
                    37, 5,45,13,53,21,61,29,
                    36, 4,44,12,52,20,60,28,
                    35, 3,43,11,51,19,59,27,
                    34, 2,42,10,50,18,58,26,
                    33, 1,41, 9,49,17,57,25,
                ]
        
        ##==========================
        ##
        ## Encryption part
        ##
        ##==========================
        
        # warp num when it is negetive
        def warpNum(value,min,max)
            if(value < min)
                value = max + value - min
            end
            return value
        end
        
        # shift bits in array(shift to left)
        def shift_bits(array,num_of_shift)
            result = Array.new(56,0)
            result.each_with_index do |x,index|
                if(index < 28)
                    result[warpNum(index-num_of_shift,0,28)] = array[index]
                else
                    result[warpNum(index-num_of_shift,28,56)] = array[index]
                end
            end
            return result
        end
        
        # 56 bits to 64 bits
        # for parity bit, I choose even parity bit
        def alter56To64(array)
            result = Array.new(64,0)
            counter = 0
            bit = 0
            array.each_with_index do |x,index|
                result[counter] = array[index]
                if ((index + 1)%7 == 0)
                    counter = counter + 1
                    result[counter] = bit
                    bit = 0
                else
                    bit = bit ^ array[index]
                end
                counter = counter + 1
            end
            return result
        end
        
        # produce sub key
        def produceSubKey(key)
            cd = Array.new(16)
            binary2 = EncryptionHeader.hex_to_binary(key,64)
            binary_array = binary2[0] 
            if (binary_array != 64)
                binary_array = alter56To64(binary_array)
            end
            array56 = EncryptionHeader.encrypt_array_with_table(binary_array,@@PC1,56)
            cd.each_with_index do |x,index|
                array56 = shift_bits(array56,@@SHIFTS[index])
                array48 = EncryptionHeader.encrypt_array_with_table(array56,@@PC2,48)
                cd[index] = array48
            end
        end
        
        # initial permutation
        def createIP(message)
            array = EncryptionHeader.transferStringToBinary(message,64)
            result = Array.new(array.size)
            array.each_with_index do |x,index|
                tmp = EncryptionHeader.EncryptionHeader.encrypt_array_with_table(x,@@IP,64)
                result[index] = tmp
            end
            return result
        end
        
        def setbits_according_to_S(array,pos,row,colum)
            s = Array.new(8)
            tmp_array = Array.new(4,0)
            s[0] = @@S1
            s[1] = @@S2
            s[2] = @@S3
            s[3] = @@S4
            s[4] = @@S5
            s[5] = @@S6
            s[6] = @@S7
            s[7] = @@S8
            pos = pos - 1
            value = s[pos][16*row+colum]
            counter = 0
            while(value != 0) do
                tmp_array[counter] = value % 2
                counter = counter + 1
                value = value / 2
            end
            tmp_array.each_with_index do |x,index|
               array[pos*4+index] = tmp_array[3 - index]   
            end
        end
        
        
        # Sboxes
        def s_boxes(array)
            result = Array.new(32,0)
            colum = 0
            row = 0
            position = 0;
            array.each_with_index do |x,index|
                position = (index + 1)%6
                if(  position == 1 )
                    row = array[index]
                elsif( position == 0 )
                    row = row * 2 + array[index]
                    setbits_according_to_S(result,(index+1)/6,row,colum)
                    colum = 0
                else
                    colum = colum + array[index] * (2 ** (5-position) ) 
                end
            end
            return result
        end
        
        
        # function f
        def functionF(array_right,sub_key)
            array_right = EncryptionHeader.encrypt_array_with_table(array_right,@@BIT_SELECTION ,48)
            array_right = EncryptionHeader.arrayXor(array_right,sub_key)
            array_right = s_boxes(array_right)
            array_right = EncryptionHeader.encrypt_array_with_table(array_right,@@P,32)
            return array_right
        end
        
        # overall encryption process
        def encrypt_binary_array(array,sub_keys)
            ip = EncryptionHeader.encrypt_array_with_table(array,@@IP,64)
            result = Array.new(64,0)
            right = Array.new(32,0)
            left = Array.new(32,0)
            ip.each_with_index do |x,index|
                if(index < 32)
                    left[index] = ip[index]  
                else
                    right[index-32] = ip[index]  
                end
            end
            for i in 1..16
                backup = EncryptionHeader.copyArray(right)
                right = EncryptionHeader.arrayXor(left,functionF(right,sub_keys[i-1]))
                EncryptionHeader.copyValue(left,backup)
            end
            
            result.each_with_index do |x,index|
                if(index < 32)
                    result[index] = right[index]  
                else
                    result[index] = left[index-32]  
                end
            end
            result = EncryptionHeader.encrypt_array_with_table(result,@@IP_1,64)
            return result
        end
        
        # encryption
        def encrypt(message,key,isString)
            result = ""
            sub_key = produceSubKey(key)
            if(isString)
                array = EncryptionHeader.transferStringToBinary(message,64)
            else
                array = EncryptionHeader.hex_to_binary(message,64)
            end
            array.each do |x|
                result = result + EncryptionHeader.binary_to_hex_sub(encrypt_binary_array(x,sub_key))
            end
            return result
        end
        
        
        ##==========================
        ##
        ## Decryption part
        ##
        ##==========================
        
        # overall decryption process
        # it almost same as encryption, thanks to Sbox
        def decrypt_binary_array(array,sub_keys)
            array = EncryptionHeader.decrypt_array_with_table(array,@@IP_1,64)
            result = Array.new(64,0)
            right = Array.new(32,0)
            left = Array.new(32,0)
            # R16L16, left = R16, right = L16.
            array.each_with_index do |x,index|
                if(index < 32)
                    left[index] = array[index]  
                else
                    right[index-32] = array[index]  
                end
            end
            for i in 1..16
                backup = EncryptionHeader.copyArray(right)
                right = EncryptionHeader.arrayXor(left,functionF(right,sub_keys[16-i]))
                EncryptionHeader.copyValue(left,backup)
            end
            
            result.each_with_index do |x,index|
                if(index < 32)
                    result[index] = right[index]  
                else
                    result[index] = left[index-32]  
                end
            end
            result = EncryptionHeader.decrypt_array_with_table(result,@@IP,64)
            return result
        end
        
        def decrypt(cipher_txt,key,isString)
            result = ""
            sub_keys = produceSubKey(key)
            array2 = EncryptionHeader.hex_to_binary(cipher_txt,64)
            array2.each do |x|
                array = decrypt_binary_array(x,sub_keys)
                if(isString)
                    result = result + EncryptionHeader.transferBinaryToString(array)
                else
                    result = result + EncryptionHeader.binary_to_hex_sub(array)
                end
            end
            return result
        end
        
        ##==========================
        ##
        ## Triple DES
        ##
        ##==========================
        
        def tripe_DES_encryption(message,key1,key2,key3)
            result = encrypt(message,key1,true)
            result = decrypt(result,key2,false)
            result = encrypt(result,key3,false)
            return result
        end
        
        def tripe_DES_decryption(cipher_txt,key1,key2,key3)
            result = decrypt(cipher_txt,key3,false)
            result = encrypt(result,key2,false)
            result = decrypt(result,key1,true)
            return result
        end
    end
    def self.encrypt( message,key1,key2,key3)
        tripe_des= TripleDES_ENCRYPTION.new
        tripe_des.tripe_DES_encryption( message,key1,key2,key3 )
    end
    def self.decrypt( cipher_txt,key1,key2,key3)
        tripe_des= TripleDES_ENCRYPTION.new
        tripe_des.tripe_DES_decryption( cipher_txt,key1,key2,key3)
    end
    def self.encrypt1(message,key)
        des = TripleDES_ENCRYPTION.new
        des.encrypt(message,key,true)
    end
    def self.decrypt1(message,key)
        des = TripleDES_ENCRYPTION.new
        des.decrypt(message,key,true)
    end
end

