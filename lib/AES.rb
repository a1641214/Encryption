
#    Declaration 
#
# 1. This program is built under the concept 
#    provided by following websites:
#    https://captanu.wordpress.com/tag/aes/
#    https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
#    https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
#    https://www.ime.usp.br/~rt/cranalysis/AESSimplified.pdf (RCON table)
#    http://www.cs.columbia.edu/~sedwards/classes/2008/4840/reports/AES.pdf 
#    https://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns

require_relative 'EncryptionHeader.rb'
module AES
    class AES_ENCRYPTION
        @@S_BOX =[
                    "63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76",
                    "ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0",
                    "b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15",
                    "04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75",
                    "09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84",
                    "53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf",
                    "d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8",
                    "51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2",
                    "cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73",
                    "60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db",
                    "e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79",
                    "e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08",
                    "ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a",
                    "70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e",
                    "e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df",
                    "8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"
                ]
        
        @@RCON_CONSTANTS=[
                            [0,0,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,0,0,0, 0,0,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,0,0,0, 0,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,0,0,0, 1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,0,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,0,0,1, 1,0,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,0,1,1, 0,1,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,1,1,0, 1,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [1,1,0,1, 1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [1,0,1,0, 1,0,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [0,1,0,0, 1,1,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
                            [1,0,0,1, 1,0,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
                        ]
        
        @@MIX_COLUM= [
                        [2,3,1,1],
                        [1,2,3,1],
                        [1,1,2,3],
                        [3,1,1,2]
                    ]
        
        @@INVERSE_MIX_COLUM =    [
                                    [14,11,13, 9],
                                    [ 9,14,11,13],
                                    [13, 9,14,11],
                                    [11,13, 9,14]
                                ]
        
        
        #=================================
        #
        # encryption
        #
        #====================================
        
        def s_box_lookup(array,start,sBox,row,colum)
            value = sBox[row*16+colum]
            binary = EncryptionHeader.hex_to_binary(value,8)
            index = 0
            while(index < 8)
                array[start+index] = binary[0][index]
                index = index + 1
            end
        end
        
        def s_box_changeArrayByRange(array,a_start,a_end)
            round = 0
            row = 0
            colum = 0
            while(a_start <= a_end)
                round = (a_start+1)%8
                if( round == 0)
                    colum = colum + array[a_start]
                    s_box_lookup(array,a_start-7,@@S_BOX,row,colum)
                    row = 0
                    colum = 0
                else
                    if(round <= 4)
                        row = row + (2**(4-round))*array[a_start]
                    else
                        colum = colum + (2**(8-round))*array[a_start]
                    end
                end
                a_start = a_start + 1
            end
        end
        
        
        def shiftArrayByRange(array,a_start,a_end,amount)
            backup = Array.new(amount,0)
            index = 0
            store_point = a_start + amount
            while(a_start <= a_end-amount)
                # store backup
                if(a_start < store_point)
                    backup[index] = array[a_start]
                    index = index + 1
                end
                array[a_start] = array[a_start + amount]
                a_start = a_start + 1
            end
            counter = 0
            while(index > 0)
                array[a_start] = backup[counter]
                a_start = a_start + 1
                index = index - 1
                counter = counter + 1
            end
        end
        
        def shift_row(array)
            round = 0
            array.each_with_index do |value,index|
                round = (index+1)%32
                if( round == 0)
                    shiftArrayByRange(array,index-31,index,8)
                end
            end
        end
        
        def mutiply(num1,num2)
            if(num2 == 1)
                return num1
            end
            backup = num1
            num1 = num1 << 1
            if(num1 >= 256)
                num1 = num1 - 256
                num1 = num1 ^ 27
            end
            if(num2 == 2)
                return num1
            end
            if(num2 == 3)
                return num1 ^ backup
            end
            if(num2 == 9)
                num1 = mutiply(num1,2)
                num1 = mutiply(num1,2)
                return num1 ^ backup
            end
            if(num2 == 11)
                num1 = mutiply(num1,2)
                num1 = num1 ^ backup
                num1 = mutiply(num1,2)
                return num1 ^ backup
            end
            if(num2 == 13)
                num1 = num1 ^ backup
                num1 = mutiply(num1,2)
                num1 = mutiply(num1,2)
                return num1 ^ backup
            end
            if(num2 == 14)
                num1 = num1 ^ backup
                num1 = mutiply(num1,2)
                num1 = num1 ^ backup
                return mutiply(num1,2)
            end
            puts "Error: " + backup.to_s + " is invalid"
            return 0
        end
        
        
        def mutiplyRow(array,a_start,a_end,matrix_row)
            counter = 0
            num = 0
            i = 0
            while(a_start <= a_end)
                num = num + (2 ** (7 - counter)) * array[a_start]
                if(counter == 7)
                    if(i == 0)
                        result = mutiply(num,matrix_row[i])
                    else
                        result = mutiply(num,matrix_row[i]) ^ result
                    end
                    num = 0
                    counter = 0
                    i = i + 1
                else
                    counter =counter + 1
                end
                a_start = a_start + 1
            end
            return result
        end
        
        
        def mutiplyMatrixInArrayRange(array,a_start,a_end,matrix)
            hex = ""
            for i in 0..3 
                num = mutiplyRow(array,a_start,a_end,matrix[i])
                if(num < 16)
                    hex = hex + "0" + num.to_s(16)
                else
                    hex = hex + num.to_s(16)
                end
            end
            binary = EncryptionHeader.hex_to_binary(hex,32)
            binary[0].each_with_index do |value,index|
                array[a_start+index] = binary[0][index]
            end
        end
        
        def mixColum(array)
            round = 0
            array.each_with_index do |value,index|
                # 4bytes = 32bits
                round = (index+1)%32
                if(round == 0)
                    mutiplyMatrixInArrayRange(array,index-31,index,@@MIX_COLUM)
                end
            end
        end
        
        
        def aes_encrypt_sub(array,sub_keys)
            # add round key
            array = EncryptionHeader.arrayXor(array,sub_keys[0])
            round = sub_keys.size - 1
            index = 1
            while(round > 0)
                s_box_changeArrayByRange(array,0,array.size-1)
                shift_row(array)
                if(round != 1)
                    # no mix colum in the last round
                    mixColum(array)
                end
                # add round key
                array = EncryptionHeader.arrayXor(array,sub_keys[index])
                round = round - 1
                index = index + 1
            end
            return array
        end
        
        def copyArrayInRange(array,a_start,a_end)
            result = Array.new(array.size,0)
            index = 0
            while(a_start <= a_end)
                result[index] = array[a_start]
                index = index + 1
                a_start = a_start + 1
            end
            return result
        end
        
        
        def produceNextSubKey(current,round)
            result = Array.new(current.size,0)
            for i in 0..31
                result[i] = current[current.size - 32 + i]
            end
            shiftArrayByRange(result,0,31,8)
            s_box_changeArrayByRange(result,0,31)
            EncryptionHeader.arrayXorByRange(result,0,31,@@RCON_CONSTANTS[round],0,31)
            EncryptionHeader.arrayXorByRange(result,0,31,current,0,31)
            loop_start = 32
            loop_end = current.size
            while( (loop_start+31) < loop_end)
                EncryptionHeader.arrayXorByRange(result,loop_start,loop_start+31,current,loop_start,loop_start+31)
                loop_start = loop_start + 32
            end
            return result
        end
        
        def aes_produceSubKey(key)
            length = key.size * 4
            round = 0
            if(length == 128)
                round = 10
            elsif(length == 192)
                round = 12
            elsif(length == 256)
                round = 14
            end
            # sub_keys
            result = Array.new
            current_subkey = EncryptionHeader.hex_to_binary(key,length)
            current_subkey = current_subkey[0]
            result.push(current_subkey)
            # Add your implementation....
            current_round = 0
            while(current_round < round)
                current_subkey = produceNextSubKey(current_subkey,current_round)
                result.push(current_subkey)
                current_round = current_round + 1
            end
            return result
        end
        
        def aes_encrypt(message,key)
            length = key.size * 4
            if(length != 128 && length != 192 && length != 256)
                puts "Error: Invalid key length."
                return nil
            end
            sub_keys = aes_produceSubKey(key)
            array2 = EncryptionHeader.transferStringToBinary(message,length)
            result = Array.new
            array2.each do |array|
                result.push( aes_encrypt_sub(array,sub_keys) )
            end
            return EncryptionHeader.binary_to_hex(result)
        end
        
        
        #===================================================
        #
        #  Decryption
        #
        #===================================================
        
        def inverse_shiftArrayByRange(array,a_start,a_end,amount)
            backup = Array.new(amount,0)
            index = 0
            store_point = a_end - amount
            loop_start = a_start + amount
            while(loop_start <= a_end)
                # store backup
                if(store_point < a_end)
                    backup[index] = array[a_end]
                    index = index + 1
                end
                array[a_end] = array[a_end - amount]
                a_end = a_end - 1
            end
            while(index > 0)
                array[a_start] = backup[index-1]
                a_start = a_start + 1
                index = index - 1
            end
        end
        
        def inverse_shift_row(array)
            round = 0
            array.each_with_index do |value,index|
                round = (index+1)%32
                if( round == 0)
                    inverse_shiftArrayByRange(array,index-31,index,8)
                end
            end
        end
        
        def putDecimalInBinaryArrayByRange(array,a_start,a_end,decimal)
            tmp = Array.new(a_end-a_start+1,0)
            index = a_end - a_start
            while(decimal > 0)
                tmp[index] = decimal%2
                index = index - 1
                decimal = decimal / 2
            end
            index = 0
            while(a_start <= a_end)
                array[a_start] = tmp[index]
                index = index + 1
                a_start = a_start + 1
            end
        end
        
        def inverse_s_box_lookup(array,a_start,s_box,value)
            str_val = value.to_s(16)
            if(str_val.size < 2)
                str_val = "0" + str_val
            end
            row = 0
            colum = 0
            s_box.each_with_index do |str,index|
                if(str_val == str)
                    break
                end
                if( (index + 1)%16 == 0)
                    row = row + 1
                    colum = 0
                else
                    colum = colum + 1
                end
            end
            if(row > 15)
                puts "Error: cannot find assigned value in s_box"
            end
            putDecimalInBinaryArrayByRange(array,a_start,a_start+3,row)
            putDecimalInBinaryArrayByRange(array,a_start+4,a_start+7,colum)
        end
        
        
        def inverse_s_box_changeArrayByRange(array,a_start,a_end)
            round = 0
            value = 0
            while(a_start <= a_end)
                round = (a_start+1)%8
                if( round == 0)
                    value = value + array[a_start]
                    inverse_s_box_lookup(array,a_start-7,@@S_BOX,value)
                    value = 0
                else
                    value = value + (2**(8-round))*array[a_start]
                end
                a_start = a_start + 1
            end
        end
        
        def inverse_mixColum(array)
            round = 0
            array.each_with_index do |value,index|
                # 4bytes = 32bits
                round = (index+1)%32
                if(round == 0)
                    mutiplyMatrixInArrayRange(array,index-31,index,@@INVERSE_MIX_COLUM)
                end
            end
        end
        
        def aes_decrpty_sub(array,sub_keys)
            # add round key
            round = sub_keys.size - 1
            ignore = round
            while(round > 0)
                # add round key
                array = EncryptionHeader.arrayXor(array,sub_keys[round])
                if(round != ignore)
                    # no mix colum in the last round
                    inverse_mixColum(array)
                end
                inverse_shift_row(array)
                inverse_s_box_changeArrayByRange(array,0,array.size-1)
                round = round - 1
            end
            array = EncryptionHeader.arrayXor(array,sub_keys[0])
            return array
        end
        
        
        def aes_decrypt(cipher_txt,key)
            result = ""
            length = key.size * 4
            if(length != 128 && length != 192 && length != 256)
                puts "Error: Invalid key length."
                return nil
            end
            sub_keys = aes_produceSubKey(key)
            array2 = EncryptionHeader.hex_to_binary(cipher_txt,length)
            array2.each_with_index do |array,index|
                binary_result = aes_decrpty_sub(array,sub_keys)
                result = result + EncryptionHeader.transferBinaryToString(binary_result)
            end
            return result
        end
    end
    def self.encrypt( message,key)
        aes = AES_ENCRYPTION.new
        aes.aes_encrypt( message,key )
    end
    def self.decrypt( cipher_txt,key)
        aes = AES_ENCRYPTION.new
        aes.aes_decrypt( cipher_txt,key )
    end
end
