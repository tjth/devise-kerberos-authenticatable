require 'devise_kerberos_authenticatable/strategy'
require 'csv'

module Devise
  module Models
    module KerberosAuthenticatable



      def self.included(base)
        base.class_eval do
          extend ClassMethods

          attr_accessor :password
        end
      end


      def clean_up_passwords
        self.password = nil
      end


      def valid_kerberos_authentication?(password)
        Devise::KerberosAdapter.valid_credentials?(self.username, password)
      end


      module ClassMethods

				codes = {"bc1" => "bm1", 
								 "mc1" => "bm1",
								 "mcai1" => "bm1",
								 "mcgvi1" => "bm1",
								 "mcip1" => "bm1",
								 "mcse1" => "bm1",
								 "bjmc1" => "jmc1",
								 "mjmc1" => "jmc1",
								 "bc2" => "bm2",
								 "mc2" => "bm2",
								 "mcai2" => "bm2",
								 "mcgvi2" => "bm2",
								 "mcip2" => "bm2",
								 "mcse2" => "bm2",
								 "bise2" => "ise2",
								 "mise2" => "ise2",
								 "bjmc2" => "jmc2",
								 "mjmc2" => "jmc2",
								 "mjmcml2" => "jmc2",
								 "bc3" => "b3",
								 "mc3" => "m3",
								 "mcai3" => "m3",
								 "mcgvi3" => "m3",
								 "mcse3" => "m3",
								 "bise3" => "ise3",
								 "mise3" => "ise3",
								 "bjmc3" => "jmcb3",
								 "mjmc3" => "jmcm3",
								 "mjmcml3" => "jmcm3",
								 "mocc3" => "o3",
								 "bxx3" => "x3",
								 "mxx3" => "x3",
								 "mc4" => "m4",
								 "mcai4" => "m4",
								 "mcgvi4" => "m4",
								 "mcip4" => "m4",
								 "mcse4" => "m4",
								 "mise4" => "ise4",
								 "mjmc4" => "jmcm4",
								 "mxx4" => "x4",
								 "pac5" => "",
								 "pres5" => "",
								 "pcsai5" => "",
								 "pcscm5" => "",
								 "pcsds5" => "",
								 "pcsml5" => "",
								 "pcsse5" => "",
								 "pcsvip5" => "",
								 "pcs5" => "",
								 "pxx5" => "x5",
								 "pci5" => "",				
								 "res6" => "",
								 "resb6" => "",
								 "rests6" => "",
								 "rxx6" => "x6",					 
								}

        def authenticate_with_kerberos(attributes = {})
          return nil unless attributes[:username].present?

          resource = all.where(:username => attributes['username']).first

          if resource.blank?
            resource = new
            resource[:username] = attributes['username']
	    			csv_text = File.read("/home/guest/webapp/student_dump.csv")
	    			csv = CSV.parse(csv_text, :write_headers => true, :headers => ["Lastname", "Firstname", "Login", "Year", "Class", "dycode", "dystring"])
	   				r = csv.find{|row|row["Login"] == attributes['username']}
	    			if r != nil then
			  		resource[:name] = r["Firstname"]
	      		resource[:name] << " "
	      		resource[:name] << r["Lastname"]
	      		resource[:dycode] = codes[r["dycode"]]
	      		resource[:dystring] = r["dystring"]
						end
          end

          if resource.try(:valid_kerberos_authentication?, attributes[:password])
            resource.save if resource.new_record?
            return resource
          else
            return nil
          end
        end
      end


    end
  end
end
