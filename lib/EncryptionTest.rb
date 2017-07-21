require_relative "AES.rb"
require_relative "TripleDES.rb"

module EncryptionTest
    class Test
        def triple_des_test(message,key1,key2,key3)
            display = ""
            display = display + "message:[" + message + "]\n"
            display = display + "key1:[" + key1 + "]\n"
            display = display + "key2:[" + key2 + "]\n"
            display = display + "key3:[" + key3 + "]\n"
            triple_des_encryption_start = Time.now
            cipher_txt = TripleDES.encrypt(message,key1,key2,key3)
            triple_des_encryption_finish = Time.now
            triple_des_encryption_time = triple_des_encryption_finish - triple_des_encryption_start
            triple_des_decryption_start = Time.now
            result = TripleDES.decrypt(cipher_txt,key1,key2,key3)
            triple_des_decryption_finish = Time.now
            triple_des_decryption_time = triple_des_decryption_finish - triple_des_decryption_start
            display = display + "Triple_des Encryption: " + triple_des_encryption_time.to_s
            display = display + "\n"
            display = display + "Triple_des Decryption: " + triple_des_decryption_time.to_s
            display = display + "\n"
            display = display + "Total time: " + (triple_des_decryption_time + triple_des_encryption_time).to_s + "\n"
            if result != message
                display = display + "Error: triple des encryption is wrong"
                display = display + "\n"
            end
            return display
        end
        
        def aes_test(message,key)
            display = ""
            display = display + "message:[" + message + "]\n"
            display = display + "key:[" + key + "]\n"
            aes_encryption_start = Time.now
            cipher_txt = AES.encrypt(message,key)
            aes_encryption_finish = Time.now
            aes_encryption_time = aes_encryption_finish - aes_encryption_start
            aes_decryption_start = Time.now
            result = AES.decrypt(cipher_txt,key)
            aes_decryption_finish = Time.now
            aes_decryption_time = aes_decryption_finish - aes_decryption_start
            display = display +  "AES Encryption: " + aes_encryption_time.to_s
            display = display + "\n"
            display = display +  "AES Decryption: " + aes_decryption_time.to_s
            display = display + "\n"
            display = display + "Total time: " + (aes_decryption_time + aes_encryption_time).to_s 
            display = display + "\n"
            if result != message
                display = display + "Error: aes encryption is wrong"
                display = display + "\n"
            end
            return display
        end
    end
    
    def self.auto_test(times,type = 0,display="",message_size = 8, i = 1)
        if(times <= 0)
            return display
        end
        test = Test.new
        o = [(' '..'~')].map(&:to_a).flatten
        p = [('0'..'9'),('a'..'f')].map(&:to_a).flatten
        message = (0...message_size).map { o[rand(o.length)] }.join
        if(type == 0)
            # key can be any chr in "0~F"
            key1 = (0...14).map { p[rand(p.length)] }.join
            key2 = (0...14).map { p[rand(p.length)] }.join
            key3 = (0...14).map { p[rand(p.length)] }.join
            display = display + "======== TripleDES Test "+ i.to_s + " =============\n"
            display = display + test.triple_des_test(message,key1,key2,key3)
        elsif type == 1
            key128 = (0...32).map { p[rand(p.length)] }.join
            display = display + "========= AES(128bits) Test "+ i.to_s + " ===========\n"
            display = display + test.aes_test(message,key128)
        elsif type == 2
            key192 = (0...48).map { p[rand(p.length)] }.join
            display = display + "========= AES(192bits) Test "+ i.to_s + " ===========\n"
            display = display + test.aes_test(message,key192)
        elsif type == 3
            key256 = (0...64).map { p[rand(p.length)] }.join
            display = display + "======= AES(256bits) Test " + i.to_s + " ======\n"
            display = display + test.aes_test(message,key256)
        end
        times = times - 1
        i = i + 1
        auto_test(times,type,display,message_size+8,i)
    end
end




