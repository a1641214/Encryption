class MyEncryption < ActiveRecord::Base
    def self.isTrue(str1,str2)
        if(str1 == str2)
            return true
        end
        return false    
    end
    def self.isValid(txt)
        txt.each_byte do |i|
            if( !((47 < i and i < 58) || (96 < i and i < 103)) )
                return false
            end
        end
        return true
    end
    
    def self.isValidAES(keys,length)
        if(keys[:key] == "")
            return "Error: You can not leave AES key empty."
        end
        size = keys[:key].size
        if(size != length/4 )
            return "Error: AES key is not " + length.to_s + "bits(" + (length/4).to_s + "chr)"
        end
        if(  (! isValid(keys[:key])) )
            return "Error: invalid key, AES key only contain 0~9 and a~f"
        end
    end
    
    def self.isValidTripleDES(keys)
        if(keys[:key1] == "" or keys[:key2] == "" or keys[:key3] == "")
            return "Error: You can not leave key1 or key2 or key3 empty."
        end
        size1 = keys[:key1].size
        size2 = keys[:key2].size
        size3 = keys[:key3].size
        if(size3 != 14 and size1 != 14 and size2 != 14)
            return "Error: key1 or key2 or key3 is not 56bits(14chr)"
        end
        if(  (! isValid(keys[:key1])) or (! isValid(keys[:key1])) )
            return "Error: invalid key, key1 and key2 only contain 0~9 and a~f"
        end
    end
    
    def self.isEncryptionValid(encryption,keys)
        if(encryption == "TripleDES")
            return isValidTripleDES(keys)
        elsif(encryption == "AES128")
            return isValidAES(keys,128)
        elsif(encryption == "AES192")
            return isValidAES(keys,192)
        elsif(encryption == "AES256")
            return isValidAES(keys,256)
        else
            return "Error: Invalid Encryption method"
        end
        return nil
    end
    def self.isDecryptionValid(decryption,cipher,keys)
        if(!isValid(cipher))
            return "Error: wrong cipher, cipher should only contain 0~9 and a~f"
        end
        return isEncryptionValid(decryption,keys)
    end
    
    def self.getType(encryption)
        if(encryption == "TripleDES")
            return 0
        elsif(encryption == "AES128")
            return 1
        elsif(encryption == "AES192")
            return 2
        elsif(encryption == "AES256")
            return 3
        end
        return 0
    end
    
    def self.runEncryption(encryption,message,keys)
        if(encryption == "TripleDES")
            return TripleDES.encrypt(message,keys[:key1],keys[:key2],keys[:key3])
        elsif(encryption == "AES128")
           return AES.encrypt(message,keys[:key])
        elsif(encryption == "AES192")
            return AES.encrypt(message,keys[:key])
        elsif(encryption == "AES256")
            return AES.encrypt(message,keys[:key])
        end
        return "Error: Programmer should never see this line"
    end
    def self.runDecryption(decryption,cipher,keys)
        if(decryption == "TripleDES")
            return TripleDES.decrypt(cipher,keys[:key1],keys[:key2],keys[:key3])
        elsif(decryption == "AES128")
           return AES.decrypt(cipher,keys[:key])
        elsif(decryption == "AES192")
            return AES.decrypt(cipher,keys[:key])
        elsif(decryption == "AES256")
            return AES.decrypt(cipher,keys[:key])
        end
        return "Error: Programmer should never see this line"
    end
end
