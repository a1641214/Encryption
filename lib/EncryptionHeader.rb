module EncryptionHeader
    ##============================
    ##
    ## helper function
    ##
    ##============================
    def self.printArray(array)
        array.each { |x| printf(x) }
        puts ""
    end

    def self.printf(str)
      print str
      $stdout.flush
    end

    def self.printTwoDimensionalArray(array2)
        array2.each { |x| printArray(x) }
    end

    # copy array
    def self.copyArray(array)
        result = Array.new(array.size,0)
        result.each_with_index do |x,index|
            result[index] = array[index]
        end
    end
    
    # copy value for array
    def self.copyValue(array,target)
        array.each_with_index do |x,index|
            array[index] = target[index]
        end
    end
    
    # Xor for binary array
    def self.arrayXor(array1,array2)
        result = Array.new(array1.size,0)
        result.each_with_index do |x,index|
            result[index] = array1[index] ^ array2[index]
        end
        return result
    end
    
    #Xor for array, only do Xor in given range, change value in first array
    def self.arrayXorByRange(array1,a1_start,a1_end,array2,a2_start,a2_end)
        while(a1_start <= a1_end)
            array1[a1_start] = array1[a1_start] ^ array2[a2_start]
            a1_start = a1_start + 1
            a2_start = a2_start + 1
        end
    end
    
    ##==========================
    ##
    ## Encryption part
    ##
    ##==========================
    
    def self.string_to_hex(str)
        result = ""
        str.each_byte do |n|
            if(n < 16)
                result = result + "0"
            end
            result = result + n.to_s(16)
        end
        return result
    end
    
    # add binary result into array
    def self.addBinaryToArray(n,r,index)
        for i in 0..3
            # reverse order
            tmp = 3 - i
            # use for check 1
            tmp = 1 << tmp
            # check whether the certain position is 1
            tmp = n & tmp
            if( tmp > 0 )
                r[index+i] = 1 
            else
                r[index+i] = 0
            end
        end
    end
    
    def self.hex_to_binary(hex,length)
        result = Array.new
        array = Array.new(length,0)
        counter = 0
        hex.each_byte do |n|
            n = n - 48
            if( n > 9 ) then
                n = n - 87 + 48
            end
            # add 0 or 1 to array. array contains binary
            addBinaryToArray(n,array,counter * 4)
            if( (counter+1) * 4 == length)
                result.push(array)
                array = Array.new(length,0)
                counter = 0;
            else
                counter = counter + 1;
            end
        end
        if(counter != 0)
            result.push(array)
        end
        return result
    end
    
    def self.transferStringToBinary(str,length)
        result = string_to_hex(str)
        result = hex_to_binary(result,length)
        return result
    end
    
    # encrypt an binary according to a table
    def self.encrypt_array_with_table(array,table,length)
        result = Array.new(length,0)
        result.each_with_index do |x,index|
            result[index] = array[table[index]-1] 
        end
        return result
    end
    
    ##==========================
    ##
    ## Decryption part
    ##
    ##==========================
    # deal with single array
    def self.binary_to_hex_sub(array)
        result = ""
        num = 0
        counter = 0
        array.each { |x|
            num = num + (2 ** (3 - counter)) * x
            counter =counter + 1
            if(counter > 3)
                result = result + num.to_s(16)
                num = 0
                counter = 0
            end
        }
        return result
    end
    
    # deal with two-dinmansional array 
    def self.binary_to_hex(array2)
        result = ""
        array2.each { |x|
            result = result + binary_to_hex_sub(x)
        }
        return result
    end
    
    def self.hex_to_string(hex)
        result = ""
        tmp = ""
        tmpi = 0
        counter = 0
        hex.each_byte do |n|
            tmp = tmp + n.chr
            counter = counter + 1
            if counter > 1
                tmpi = tmp.to_i(16)
                if(tmpi == 0)
                    return result
                end
                result = result + tmpi.chr
                tmp = ""
                counter = 0
            end
        end
        return result
    end
    
    def self.transferBinaryToString(binary_array)
        hex = binary_to_hex_sub(binary_array)
        return hex_to_string(hex)
    end
    
    # decrypt binary_array back to its original form
    def self.decrypt_array_with_table(array,table,length)
        result = Array.new(length,0)
        result.each_with_index do |x,index|
            result[table[index]-1] = array[index] 
        end
        return result
    end
end
