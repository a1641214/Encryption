require 'AES'
require 'TripleDES'
require 'EncryptionTest'
class EncryptionController < ApplicationController
    def index
    end
    
    # when user submit a request, we do encryption or decryption
    def create
        if(params[:commit] != nil)
            session[:encryption] = params[:encryption]
            session[:message] = params[:message]
            session[:cipher] = params[:cipher]
            keys = params[:keys]
            session[:key] = keys[:key]
            session[:key1] = keys[:key1]
            session[:key2] = keys[:key2]
            session[:key3] = keys[:key3]
        end
        if(params[:commit] == "Encrypt")
            invalid = MyEncryption.isEncryptionValid(params[:encryption],params[:keys])
            if(invalid == nil)
                start = Time.now
                session[:cipher] = MyEncryption.runEncryption(params[:encryption],params[:message],params[:keys])
                finish = Time.now
                flash[:time] = (finish- start).to_s
            else
                flash[:error] = invalid
            end
        elsif (params[:commit] == "Decrypt")
            invalid = MyEncryption.isDecryptionValid(params[:encryption],params[:cipher],params[:keys])
            if(invalid == nil)
                start = Time.now
                session[:message] = MyEncryption.runDecryption(params[:encryption],params[:cipher],params[:keys])
                finish = Time.now
                flash[:time] = (finish- start).to_s
            else
                flash[:error] = invalid
            end
        elsif (params[:commit] == "Auto Test")
            start = Time.now
            session[:message] = EncryptionTest.auto_test(50,MyEncryption.getType(session[:encryption]))
            finish = Time.now
            flash[:time] = (finish- start).to_s
        else
            #flash[:error] = "Invalid request"
        end
        redirect_to encryption_index_path
    end
    def download
        @path = File.join(Rails.root, "lib")
        if(params[:id] == "1")
            send_file( File.join(@path, "EncryptionHeader.rb"),:type => 'text/html; charset=utf-8')
        elsif(params[:id] == "2")
            send_file( File.join(@path, "TripleDES.rb"))
        elsif(params[:id] == "3")
            send_file( File.join(@path, "AES.rb"))
        elsif(params[:id] == "4")
            send_file( File.join(@path, "EncryptionTest.rb"))
        end
    end
end
