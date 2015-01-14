require 'socket'
require 'uri'

class PhateClient

	public 

	def initialize()
	end

	def connect(host, port)
		if (host.nil? || port.nil?)
			raise "No host or port provided"
		end

		if (@connected == true)
			raise "Already connected"
		end

		@connected = true

		@host = host
		@port = port

		@socket = TCPSocket.new(@host, @port)
		if @socket == nil
			raise "Error creating socket"
		end

		print (flush_device() + "\n")
		

		print(send_cmd(".phate?send_output_length=true&send_prompt=false")+"\n")
		

	end

	def disconnect
		if (@connected != true)
			raise 'Not connected'
		end

		@connected = false

		@socket.close
		@socket = nil
	end

	def reconnect
		if (@connected == true)
			raise "Already connected"
		end

		if (@host == nil || @port == nil)
			raise "No host or port provided"
		end

		connect(@host, @port)
	end

	def registry(hive = nil)

		if (@registry == nil) 
			@registry = PhateRegistry.new(self)
		end

		@registry.load(hive)

		return @registry
	end




	#private

	def write_to_device(data)
		@socket.puts data
		@socket.flush
	end

	def flush_device()
		out = ""

		while (IO::select([@socket], nil, nil, 1) != nil)
			out = out + @socket.read_nonblock(1024)
		end

		return out
	end

	def send_cmd(data)
		out = ""

		#binding.pry
		print ("\tSending #{data}\n")
		@socket.puts data
		@socket.flush
		
		len = @socket.read(4).unpack("N")[0]
		if (len == 0xd0a0d0a)
			len = @socket.read(4).unpack("N")[0]
		end
		print "\treceived length 0x#{len.to_s(16)}\n"
		out = @socket.read(len)
		#print "\treceived data #{out}\n"

		return out
	end

end

class PhateRegistry

	def self.hklm
		:HKEY_LOCAL_MACHINE
	end

	def self.hku
		:HKEY_USERS
	end

	

	def initialize(phate)
		@hives = {}
		#add_hive(:HKEY_LOCAL_MACHINE)
		#add_hive(:HKEY_USERS)

		@kc = phate

	end

	def [](idx)
		if @hives[idx] == nil
			raise "Invalid hive"
		else
			@hives[idx]
		end
	end

	def load(hive = nil)
		if hive == :HKEY_USERS
			@hives[:HKEY_USERS] = parse_data("HKEY_USERS\\", @kc.send_cmd("regenum?hive=HKEY_USERS"),0)
		elsif hive == :HKEY_LOCAL_MACHINE	
			@hives[:HKEY_LOCAL_MACHINE] = parse_data("HKEY_LOCAL_MACHINE\\", @kc.send_cmd("regenum?hive=HKEY_LOCAL_MACHINE"),0)
		elsif hive == nil
			#do all
			@hives[:HKEY_USERS] = parse_data("HKEY_USERS\\", @kc.send_cmd("regenum?hive=HKEY_USERS"),0)
			@hives[:HKEY_LOCAL_MACHINE] = parse_data("HKEY_LOCAL_MACHINE\\", @kc.send_cmd("regenum?hive=HKEY_LOCAL_MACHINE"),0)
		else #something else passed in
			raise "Invalid parameter"
		end

		true

	end

	private

	def add_hive(hivename)
		@hives[hivename] = {}
	end

	def parse_data(input_path, data, ilvl)
		if (input_path == "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Aliases\\Members\\S-1-5-21-2702878673-795188819-444038987\\00000ADD")
			#binding.pry
		end

		if (data == nil || data == "" || data.start_with?("Error querying Registry") == true)
				hive, path = input_path.split("\\", 2)
				print ("="*ilvl)+input_path + ": Error querying Registry\n"
				return {:hive => hive, :path => path, :error => "Error querying Registry"}
		end

		perms = nil
		other = nil
		keyname = nil
		owner = nil
		group = nil
		access_list = nil
		sid = nil
		flags=nil
		acls = nil
		hive = nil
		path = nil
		subkeys=nil
		values=nil
		value_arr=nil
		val_name=nil
		val_type=nil
		val_value=nil
		value_node=nil
		subkey_arr=nil
		subkey=nil
		

		clean_data = data.split("\r\n").collect{|x| if x != "" then x else nil end }.compact.join

		# split out permissions, subkeys and values
		perms, other = clean_data.split("Subkeys:")
		

		perms = perms.split("\t")
		keyname = perms.shift

		print (">"*ilvl)+"#{keyname}: start\n"
		
		
		owner = perms.shift.sub("Owner: ","")
		group = perms.shift.sub("Group: ","")

		access_list = {}
		while perms.length >= 3
			sid, flags, acls = perms.shift(3)

			acls = acls.sub("Access: ", "").split
			flags = flags.sub("Flags: ", "").split
			
			if (sid.start_with?("Allowed: ") == true)
				# access allowed ace
				access_list[sid.sub("Allowed: ","")] = {:acls => acls, :flags => flags}
			elsif (sid.starts_with("Denied: ") == true)
				raise "Denied ACE not yet implemented"
			else
				raise "Neither allowed nor denied ACE!"
			end
		end

		# hive, path values
		hive, path = keyname.split("\\", 2) 

		subkeys, values = other.split("Values:")

		# need to do values
		value_arr = []
		if (values != nil && values.empty? != true)
			values.strip.split("\t").each do |v|
				val_name, val_type, val_value = v.scan(/(.+) \[(.+)\]: (.+)/).flatten

				value_node = {}

				value_node[val_name] = {:type => val_type, :value => val_value}

				value_arr << value_node
			end
		end

		#recurse over subpaths
		subkey_arr = []
		if (subkeys != nil && subkeys.empty? == false)
			subkeys.strip.split("\t").each do |k|
				if (path == "")
					subkey = k
				else
					subkey = path + "\\" + k
				end
				subkey_arr << parse_data(hive+"\\"+subkey, @kc.send_cmd("regenum?hive=#{URI.encode(hive)}&path=#{URI.encode(subkey)}"),ilvl+1)
			end
		end

		

		node = {:hive => hive, 
				:path => path, 
				:owner => owner,
				:group => group,
				:access_list => access_list, 
				:values => value_arr, 
				:subkeys => subkey_arr}

		print ("<"*ilvl)+"#{keyname}: done\n"

		return node
	end

	public 

	def save(filename)
		begin
			output = File.new(filename, "w")
			output.write(@hives.to_yaml)
			output.close
		rescue Exception => e
			print "Error: " + e.to_s + " saving contents\n"
		end
	end

end

if false
	load 'phate_client.rb'
	pc = PhateClient.new
	pc.connect("10.75.77.121", 7890)
	reg_usr = pc.registry(:HKEY_USERS)
	reg_sys = pc.registry(:HKEY_LOCAL_MACHINE)
	reg_usr.save("windows_phone_8_nokia_822_registry_users.yaml")
	#hku_out = reg[:HKEY_USERS].to_yaml
	#reg_usr2 = YAML.load_file("windows_phone_8_nokia_822_registry_users.yaml")
	reg_sys.save("windows_phone_8_nokia_822_registry_local_machine.yaml")
	#hklm_out = reg[:HKEY_LOCAL_MACHINE].to_yaml
	#reg_sys = YAML.load_file("windows_phone_8_nokia_822_registry_local_machine.yaml")
	#HKEY_LOCAL_MACHINE\SYSTEM\DriverDatabase\DeviceIds\SBP2
	pc.disconnect

	pc.send_cmd("regenum?hive=HKEY_USERS&path=.DEFAULT")
end