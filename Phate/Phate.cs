using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace Phate
{
    public class Phate : IDisposable
    {
        #region Static Class

        private static StreamSocketListener listener = null;
        private static string port = "7890";
        private static string hostname = null;
        private string[] hives = { "HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_PERFORMANCE_DATA", "HKEY_CURRENT_CONFIG", "HKCR", "HKCU", "HKLM", "HKU", "HKPD", "HKCC" };
        private static System.Windows.Controls.TextBox _s_statusBlock;
        private static System.Windows.Controls.TextBlock _s_outputBlock;

        private static List<System.Threading.Thread> _s_thread_list;

        public async static void Initialize(System.Windows.Controls.TextBox statusBlock, System.Windows.Controls.TextBlock outputBlock)
        {

            _s_statusBlock = statusBlock;
            _s_outputBlock = outputBlock;

            _s_statusBlock.Text += "This is sample status." + Environment.NewLine;
            _s_outputBlock.Text += "This is sample output." + Environment.NewLine;

            // get IP address
            try
            {
                IReadOnlyList<Windows.Networking.HostName> hostnames =  Windows.Networking.Connectivity.NetworkInformation.GetHostNames();
                for (int i = 0; i < hostnames.Count; i++)
                {
                    if (hostnames[i].RawName.Substring(0, 3) == "169")
                        continue; // DHCP self-assigned address

                    if (hostnames[i].RawName.Contains(':') == true)
                        continue; //ipv6 not supported yet

                    hostname = hostnames[i].CanonicalName;
                    break;
                }

                
            }
            catch (Exception e)
            {
                _s_outputBlock.Text += "Error Binding To Socket: " + e.Message + Environment.NewLine;
            
            }
            

            // Start server
            if (listener == null)
            {
                listener = new StreamSocketListener();
                listener.ConnectionReceived += OnConnection;

                try
                {
                    await listener.BindEndpointAsync(new Windows.Networking.HostName(hostname), port);
                    _s_statusBlock.Text = System.DateTime.Now.ToString() + " Listening on " + hostname + ":" + port + Environment.NewLine;

                    _s_thread_list = new List<System.Threading.Thread>();
                }
                catch (Exception e)
                {
                    _s_statusBlock.Text = System.DateTime.Now.ToString() + " Error binding to port " + port + ". Code " + e.HResult.ToString() + Environment.NewLine;
                    throw e;
                }
            }
        }

        private static int connection_id = 0;
        private static void OnConnection(StreamSocketListener sender, StreamSocketListenerConnectionReceivedEventArgs args)
        {
            Phate repl = new Phate(_s_statusBlock, _s_outputBlock, args.Socket, (connection_id++).ToString());
            System.Threading.Thread repl_thread = new System.Threading.Thread(repl.Run);
            _s_thread_list.Add(repl_thread);
            MainPage._active_connections.Add(repl);
            repl_thread.Start();
        }

        #endregion

        #region Instanced Class

        private System.Windows.Controls.TextBox _statusBlock = null;
        private System.Windows.Controls.TextBlock _outputBlock = null;

        private StreamSocket _socket = null;
        DataWriter _to_remote = null;
        DataReader _from_remote = null;

        // code to keep the app running in the background
        private Windows.Devices.Geolocation.Geolocator _locator = new Windows.Devices.Geolocation.Geolocator();

        private bool _running = false;
        private string _instance_name = null;

        // 'typedef' for command handlers
        // Socket is passed in case the command wants to ask for user input (sub commands and such)
        public delegate string CommandHandler(StreamSocket s, Dictionary<string, List<string>> args);
        
        // map of command handlers
        private Dictionary<string, CommandHandler> _commands = new Dictionary<string, CommandHandler>();

        // Phate Server options
        private Dictionary<string, string> _options = new Dictionary<string,string>();
       

        public Phate(System.Windows.Controls.TextBox statusBlock, System.Windows.Controls.TextBlock outputBlock, StreamSocket Socket, string name = "")
        {
            _statusBlock = statusBlock;
            _outputBlock = outputBlock;
            _socket = Socket;
            _instance_name = name;

            _to_remote = new DataWriter(_socket.OutputStream);
            _from_remote = new DataReader(_socket.InputStream);

            _locator.DesiredAccuracy = Windows.Devices.Geolocation.PositionAccuracy.High;
            _locator.MovementThreshold = 50;

            _locator.StatusChanged += _locator_StatusChanged;
            _locator.PositionChanged += _locator_PositionChanged;

            libPhate.Initialize();

            _init_options();

            _init_commands();

            _console_status_msg(String.Format("Connection from {0}\n", _socket.Information.RemoteAddress.CanonicalName));              
        }

        void _locator_PositionChanged(Windows.Devices.Geolocation.Geolocator sender, Windows.Devices.Geolocation.PositionChangedEventArgs args)
        {
            Windows.Devices.Geolocation.Geocoordinate coord = args.Position.Coordinate;

        }

        void _locator_StatusChanged(Windows.Devices.Geolocation.Geolocator sender, Windows.Devices.Geolocation.StatusChangedEventArgs args)
        {
            Windows.Devices.Geolocation.PositionStatus coord = args.Status;
        }

        public bool Running() { return _running; }

        private void _init_options()
        {
            _options["send_output_length"] = "false";
            _options["send_prompt"] = "true";

        }

        private bool _init_commands()
        {
            AddCommand(".phate", _do_phate_command); 
            AddCommand("quit", _do_quit);
            AddCommand("test", _do_test);
            AddCommand("TERMINATE", _do_terminate);  // capitalized to test the case-insensitivity
            AddCommand("dlload", _do_load);
            AddCommand("help", _do_help);
            AddCommand("pid", _do_pid);
            AddCommand("open", _do_open);
            AddCommand("close", _do_close);
            AddCommand("pwd", _do_pwd);
            AddCommand("cd", _do_cd);
            AddCommand("ls", _do_dir);
            AddCommand("dir", _do_dir);
            AddCommand("exec", _do_exec);
            AddCommand("rundll", _do_rundll);
            AddCommand("whoami", _do_whoami);
            AddCommand("cat", _do_cat);
            AddCommand("burn", _do_burn);
            AddCommand("launch", _do_launch);
            AddCommand("handles", _do_handles);
            AddCommand("mit", _do_mitigations);
            AddCommand("mem", _do_memory);
            AddCommand("regread", _do_reg_read);
            AddCommand("regenum", _do_reg_enum);
            AddCommand("regwrite", _do_reg_write);
            AddCommand("chown", _do_chown);
            AddCommand("chgroup", _do_chgroup);
            AddCommand("chmod", _do_chmod);

            return true;
        }

        private void _console_status_msg(string str)
        {
            _statusBlock.Dispatcher.BeginInvoke(delegate()
            {
                _statusBlock.Text += System.DateTime.Now.ToString() + "\t" + _instance_name + ":\t" + str;
            });

        }

        private void _console_output_msg(string str)
        {
            _outputBlock.Dispatcher.BeginInvoke(delegate()
            {
                _outputBlock.Text += System.DateTime.Now.ToString() + "\t" + _instance_name + ":\t" + str;
            
            });

        
        }

        private async void _send(string str)
        {
            if (_options["send_output_length"] == "true")
                _to_remote.WriteInt32(Encoding.UTF8.GetByteCount(str));
           
            _to_remote.WriteString(str);
            await _to_remote.StoreAsync();
        }

        private string _recv()
        {
            StringBuilder sb = new StringBuilder();
            char b = '\x00';
            try
            {
                do
                {
                    _from_remote.LoadAsync(1).AsTask().Wait();

                    b = (char)_from_remote.ReadByte();

                    sb.Append(b);

                } while (b != '\x0a');

                return sb.ToString();
            }
            catch (Exception e)
            {
                _console_status_msg("Remote end terminated connection!" + Environment.NewLine);

                return "quit";
            }

        }

        public void Run()
        {
            _send("Hello from " + _socket.Information.LocalAddress.CanonicalName + Environment.NewLine);

            _running = true;
            do
            {
                _prompt();
                _print(_eval(_read())); //oh wow, such REPL
            } while (_running == true);

            _console_output_msg("Connection Terminated!" + Environment.NewLine);
            this.Dispose();
        }

        public void Print(string outp) { _print(outp); }

        private void _print(string outp)
        {
            if (outp == "")
                return;

            _console_output_msg("Sending: " + outp + Environment.NewLine);

            _send(outp + Environment.NewLine);
        }

        private string _eval(string inp)
        {
            string outp = "";

            string cmd;
            Dictionary<string, List<string>> args;

            _crack_command(inp, out cmd, out args);

            if (_commands.ContainsKey(cmd))
            {
                outp = _commands[cmd](_socket, args);
            }
            else if (cmd == "")
            { 
                // no cmd entered?
                outp = "";
            }
            else
            {
                outp = "Error, unknown command: " + cmd;
            }
            
            return outp;
        }

        //HACK: Spoof input to run a command at connect
        //TODO: good for testing - should add this as a config option
        private bool _queued_cmd_run_once = false; // set to not run by default
        private string _queued_cmd = "regwrite?hive=HKEY_CURRENT_USER&value=mykey&toWrite=abc&type=string";

        private string _read()
        {
            string inp;

            if (_queued_cmd_run_once == true && _queued_cmd != null && _queued_cmd != "")
            {
                inp = _queued_cmd;
                _queued_cmd_run_once = false;
            }
            else
                inp = _recv().Trim();

            _console_output_msg("Received: " + inp + Environment.NewLine);
            
            return inp;
        }

        private void _prompt()
        {
            if(_options["send_prompt"] == "true")
                _send("> ");

            return;
        }

        public void Dispose()
        {
            if (_to_remote != null)
                _to_remote.Dispose();
            
            if (_from_remote != null)
                _from_remote.Dispose();

            if (_socket != null)
                _socket.Dispose();
        }

        // New: Added support for encoded ampersands (i.e. '%26' == '&'
        private bool _crack_command(string raw_data, out string cmd, out Dictionary<string, List<string>> args)
        {

            string[] tokens = raw_data.Split(new char[] { '?' }, 2);

            cmd = tokens[0].ToLower();

            args = new Dictionary<string, List<string>>();

            if (tokens.Length == 2)
            {
                string[] arg_tokens = tokens[1].Split(new char[] { '&' });

                foreach (string s in arg_tokens)
                {
                    string [] kv_pair = s.Split(new char[] { '=' });
                    string val;

                    if (kv_pair.Length == 2)
                        val = kv_pair[1];   // parameter with (possibly missing) value: foo?bar=baz or foo?bar= Missing values are marshalled as empty strings (e.g. "")
                    else if (kv_pair.Length == 1)
                        val = "";           // flag-style parameter: foo?bar Set to empty strings to match the missing value case above
                    else
                        continue;           // should never get here(?) - just skip this kv-pair

                    // URI decode - this is overkill when all I really want is to decode ampersands, but it's 'safer' than doing it by hand (?)
                    string key = System.Uri.UnescapeDataString(kv_pair[0]);
                    val = System.Uri.UnescapeDataString(val);

                    if (args.ContainsKey(key)) // already exists, add it to the list
                    {
                        args[key].Add(val);
                    }
                    else // new key
                    {
                        args[key] = new List<string>();
                        args[key].Add(val);
                    }
                }
            }

            return true;
            
        }

        public bool AddCommand(string cmd, CommandHandler handler)
        {
            if (_commands.ContainsKey(cmd.ToLower()))
            {
                // command already exists
                return false;
            }
            else
            {
                _commands[cmd.ToLower()] = handler;
            }

            return true;
        }

        #endregion

        #region phate commands

        private string _do_phate_command(StreamSocket s, Dictionary<string, List<string>> args)
        {
            // these are commands that modify how the client acts

            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine(".phate?<option1>(&<option2>...): Sets options for the server.");
                sb.AppendLine("");
                sb.AppendLine("Without any options, will display the current option settings ");
                sb.AppendLine("Available Options");
                sb.AppendLine("\tsend_output_length=<true|false>: Instructs Phate to send the length of the output (as a 32-bit value) before sending the string itself. For use by automated clients.");
                sb.AppendLine("\tsend_prompt=<true|false>: Instructs Phate to send the length of the output (as a 32-bit value) before sending the string itself. For use by automated clients.");

                return sb.ToString();
            }

            if (args.Keys.Count == 0)
            {
                StringBuilder sb = new StringBuilder();

                // Display the current settings
                foreach (KeyValuePair<string, string> kvp in _options)
                {
                    sb.AppendLine(kvp.Key + ":\t" + kvp.Value);
                }

                return sb.ToString();
            }

            foreach (KeyValuePair<string, List<string>> kvp in args)
            {
                if (_options.ContainsKey(kvp.Key))
                {
                    _options[kvp.Key] = kvp.Value[0].ToLower();
                }
                else
                { 
                    // Unknown option                     
                }
            }

            return "Options set\n";    
        }

        #endregion

        #region command handlers

        // Command handlers go here - they are INSTANCE functions (at least at the moment...)

        private string _do_quit(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
                return "quit: Closes the network session, but the app continues to run and accept new connections\n";
            else
            {
                _running = false;

                return "";
            }
        }

        private string _do_test(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
                return "test: Returns a static message to verify that the app is working\n";
            else
                return "Test successful!";
        }

        private string _do_terminate(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
                return "terminate: Immediately kills the application (does not give it a chance to clean up!)\n";
            else
            {
                App.Current.Terminate();
                return ""; // never reached
            }
        }

        private string _do_help(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("help: Displays available commands and options.");
                sb.AppendLine("");
                sb.AppendLine("Without any options, will display the list of implemented commands.");
                sb.AppendLine("Optional Parameters");
                sb.AppendLine("\t{cmd}: Will display the help for {cmd}. Equal to calling cmd?help.");

                return sb.ToString();
            }

            string output = "";

            if (args.Keys.Count > 0)
            {
                string cmd = args.Keys.First();
                // Display the help for the first arg present
                if (_commands.ContainsKey(cmd) == true)
                {
                    // run cmd?help and output that info
                    Dictionary<string, List<string>> help_param = new Dictionary<string, List<string>>();
                    help_param["help"] = new List<string>();
                    help_param["help"].Add("");

                    output = _commands[cmd](s, help_param);
                }
                else
                {
                    output = String.Format("Error: There is no command \"{0}\"\n", cmd);
                }
            }
            else
            {
                // Display all the available commands
                IEnumerable<string> cmds = _commands.Keys.OrderBy(x => x);
                foreach (string k in cmds)
                {
                    output += k + Environment.NewLine;
                }
            }

            return output;
        }

        private string _do_load(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("load: Loads a dll into the process");
                sb.AppendLine("");
                sb.AppendLine("Required parameters");
                sb.AppendLine("\tname={value}: the name of the dll to load. Uses the standard Windows search algorithm. Can be repeated to load multiple dlls at once.");

                return sb.ToString();
            }

            if (args.ContainsKey("name") == false) return "Error: Required parameter, name={value}, missing.";

            string output = "";
            UInt64 addr;
            foreach (string n in args["name"])
            {
                addr = 0;
                output += "Loading " + n + ": ";
               
                if ((addr = libPhate.LoadLibrary(n, 0)) == 0)
                    output += "failed\t";
                else
                    output += "succeeded (0x" + addr.ToString() + ")\t";

                output += Environment.NewLine;
            }

            return output;
        }

        private string _do_pid(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("pid: Retrieves process identifiers");
                sb.AppendLine("");
                sb.AppendLine("Without any parameters returns the process id and a handle id for the current process");
                sb.AppendLine("Optional Parameters");
                sb.AppendLine("\tlist: Enumerates the ids for all visible processes.");
                sb.AppendLine("\tid={value}: Attempts to open and return a handle to the specified process. Can be used in conjunction with the access parameter. Defaults to the current process.");
                sb.AppendLine("\taccess={value}: Specifies the type of access to try to open the process with. Defaults to PROCESS_LIMITED_INFO (0x1000). Specify in decimal.");
                sb.AppendLine("\tinfo: Retrieves information for a given process by handle. Requires handle={value} parameter. At the moment only returns the file name of the associated process.");

                return sb.ToString();
            }

            if (args.ContainsKey("list"))
                return _pid_do_list(s, args); // short circuit for process listing

            if (args.ContainsKey("info"))
                return _pid_do_info(s, args); // short circuit for process listing


            UInt64 pid;
            if (args.ContainsKey("id"))
            {
                if (UInt64.TryParse(args["id"][0], out pid) == false)
                {
                    pid = libPhate.GetCurrentProcessId();
                }
            }
            else
                pid = libPhate.GetCurrentProcessId();

            UInt64 access;
            if (args.ContainsKey("access"))
            {
                if (UInt64.TryParse(args["access"][0], out access) == false)
                {
                    access = 0x1000; // limited info
                }
            }
            else
                access = 0x1000; // limited info

            UInt64 my_hproc = libPhate.OpenProcess(pid, access);

            return "PID: " + pid.ToString() + "\tHandle: " + my_hproc.ToString();
        }

        private string _pid_do_list(StreamSocket s, Dictionary<string, List<string>> args)
        {
            IList<UInt64> pid_list = libPhate.ListProcesses();
            string output = "Process IDs" + Environment.NewLine;
            foreach (UInt64 p in pid_list)
            {
                output += p.ToString() + Environment.NewLine;
            }
            return output;

        }

        private string _pid_do_info(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (!args.ContainsKey("handle")) return "Error: Required parameter, handle={value}, missing.";

            UInt64 hproc = 0;
            UInt64.TryParse(args["handle"][0], out hproc);

            return libPhate.GetProcessName(hproc);
        }

        private string _do_open(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("open: opens a file, returning a reference to the file which can be passed to the close command.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tname={value}: The name of the file to open. Required.");
                sb.AppendLine("\tmode={value}: The mode to open the file with. Uses fopen-style mode strings (e.g. r|w|a). Required.");

                return sb.ToString();
            }
            if (!args.ContainsKey("mode")) return "Error: Required parameter, mode={value}, missing.";
            if (!args.ContainsKey("name")) return "Error: Required parameter, name={value}, missing.";

            string filename = args["name"][0];
            string mode = args["mode"][0];


            return libPhate.OpenFile(filename, mode).ToString(); ;
        }

        private string _do_close(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("close: closes a file opened with \"open\".");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tref={value}: The reference to close. Required.");

                return sb.ToString();
            }
            if (!args.ContainsKey("ref")) return "Error: Required parameter, ref={value}, missing.";

            string str_ptr = args["ref"][0];
            UInt64 ptr;
            if (UInt64.TryParse(str_ptr, out ptr) == false)
                return "Error: Unable to parse " + str_ptr;
    
            return libPhate.CloseFile(ptr).ToString(); ;
        }

        private string _do_pwd(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
                return "pwd: Displays the current directory.";

            return libPhate.GetCurrentDirectory();
        }

        private string _do_dir(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();
                
                sb.AppendLine("dir/ls: Display a directory listing.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tpath: The path to list the contents of. Can accept wildcards in file names. Default is the current directory.");
                sb.AppendLine("\tflags: Bits that modify the information displayed (default is no flags set):");
                sb.AppendLine("\t\t 1 = Display ACL information");
                sb.AppendLine("\tSum the flags together to pass more than one");

                return sb.ToString();
                
            }
            // Flags: (see header file for LS_FLAGS enum)
            //    0x1 = display ACL info
            //    0x80000000 = path is file, not dir. doesn't have to be explicitly set

            string path = "", output = "";
            uint flags = 0;

            if (args.ContainsKey("path"))
                path = args["path"][0];

            if (args.ContainsKey("flags"))
                if (false == uint.TryParse(args["flags"][0], out flags))
                {
                    output += "Warning: Unable to parse flags" + Environment.NewLine;
                    flags = 0;
                }

            if (path != "" && System.IO.Directory.Exists(path) == false && System.IO.File.Exists(path) == true)
                flags |= 0x80000000; // set is_file

            output += libPhate.ListDirectory(path, flags);
            return output;
        }

        private string _do_cd(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("cd: Change the current directory.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tpath={value}: The new path. Required.");

                return sb.ToString();
            }
            if (!args.ContainsKey("path")) return "Error: Required parameter, path={value}, missing.";

            string path = args["path"][0];

            string err = libPhate.ChangeDirectory(path);

            if (err != null && err.Length != 0 && err != "")
                return "Error: Command returned " + err;
            else
                return _do_pwd(s, args);
        }

        private string _do_exec(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("exec: Executes a program.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tcmd: The application to run. Required.");

                return sb.ToString();
            }
            if (!args.ContainsKey("cmd")) return "Error: Required parameter, cmd={value}, missing.";

            string cmd = args["cmd"][0];
            long ret = libPhate.CreateProcess(cmd);
            if (ret > 0)
                return "Process started with pid:" + ret.ToString();
            else
                return "Error: " + libPhate.errorToString((uint)(ret * -1));
        }


        private string _do_rundll(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("rundll: Executes a function exported by a dll.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tlib: The library to load. Required.");
                sb.AppendLine("\tfunc: The function to execute. Required.");
                sb.AppendLine("\targ{0-11}={value}: An argument to pass to the function. This command can handle up to twelve arguments.");
                sb.AppendLine("\ttype{0-11}={value}: The type of the corresponding argument. This command can handle up to twelve arguments.");
                sb.AppendLine("\t\tValid types are \"int\" (signed integer), \"uint\" (unsigned integer), \"str\" (Unicode string), or \"astr\" (ASCII string).");

                return sb.ToString();
            }

            if (!args.ContainsKey("lib")) return "Error: Required parameter, lib={value}, missing.";
            if (!args.ContainsKey("func")) return "Error: Required parameter, func={value}, missing.";

            string lib = args["lib"][0];
            string func = args["func"][0];

            var types = new List<string>();
            var values = new List<string>();
            int count = 0;
            while (true)
            {
                if (!args.ContainsKey("arg" + count.ToString()) || !args.ContainsKey("type" + count.ToString())) break; //we have exausted all the params
                values.Add(args["arg" + count.ToString()][0]);
                types.Add(args["type" + count.ToString()][0]);
                count++;
            }

            Int64 ret = libPhate.RunDLL(lib, func, values.ToArray(), types.ToArray(), count);
            return "Info: Call to " + lib + ":" + func + " returned: " + ret.ToString();
        }

        private string _do_reg_read(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("regread: Reads data from the registry");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tType: The type of data to read from the registry. Must be one of: 'binary', 'dword', 'qword', 'string', 'multistring'. Required.");
                sb.AppendLine("\tHive: The registry hive to read from. Must be one of: 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_PERFORMANCE_DATA', 'HKEY_CURRENT_CONFIG', or one of their shortcuts ('hkcu', 'hkcu', etc). Required.");
                sb.AppendLine("\tPath: The name of the registry key. Must be a subkey of the Hive specified. If not specific, the default key will be used.");
                sb.AppendLine("\tValue: The name of the registry value to be read from the specified key. If it is not specified, the default (unnamed) value will be used. ");

                return sb.ToString();
            }
            if (!args.ContainsKey("type")) return "Error: Required parameter 'type' missing.";
            if (!args.ContainsKey("hive")) return "Error: Required parameter 'hive' missing.";
            string type = args["type"][0]; //do stuff here
            string hive = args["hive"][0];
            if (!hives.Contains(hive.ToUpper()))
                return "Invalid hive name! Must be one of : 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_PERFORMANCE_DATA', 'HKEY_CURRENT_CONFIG' , or their appropriate shortcut ('hkcr', 'hkcu', etc).";
            string path;
            if (!args.ContainsKey("path"))
                path = "";
            else
                path = args["path"][0];
            string value;
            if (!args.ContainsKey("value"))
                value = "";
            else
                value = args["value"][0];
            if (type == "binary")
                return libPhate.ReadBinary(hive,path,value);
            if(type == "dword")
                return libPhate.ReadDWORD(hive, path, value);
            if (type == "qword")
                return libPhate.ReadQWORD(hive, path, value);
            if(type == "string")
                return libPhate.ReadString(hive, path, value);
            if (type == "multistring")
                return libPhate.ReadMultiString(hive, path, value);

            return "Invalid type! Try again"; 
        }

        private string _do_reg_enum(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("regenum: Enumerates the subkeys and values of a key in the registry");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tHive: The registry hive to read from. Must be one of: 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_PERFORMANCE_DATA', 'HKEY_CURRENT_CONFIG', or one of their shortcuts ('hkcu', 'hkcu', etc). Required.");
                sb.AppendLine("\tPath: The name of the registry key. Must be a subkey of the Hive specified. If not specific, the default key will be used.");


                return sb.ToString();
            }

            if (!args.ContainsKey("hive")) 
                return "Error: Required parameter 'hive' missing.";

            string hive = args["hive"][0];

            if (!hives.Contains(hive.ToUpper()))
                return "Invalid hive name! Must be one of : 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_PERFORMANCE_DATA', 'HKEY_CURRENT_CONFIG' , or their appropriate shortcut ('hkcr', 'hkcu', etc).";

            string path = "";

            if (args.ContainsKey("path"))
                path = args["path"][0];

           return libPhate.EnumRegKey(hive, path);

        }


        private string _do_reg_write(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("regread: Writes data to the registry");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tType: The type of data to write to the registry. Must be one of: 'binary', 'dword', 'qword', 'string', 'multistring'. Required.");
                sb.AppendLine("\tHive: The registry hive to write to. Must be one of: 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_PERFORMANCE_DATA', 'HKEY_CURRENT_CONFIG', or one of their shortcuts ('hkcu', 'hkcu', etc). Required.");
                sb.AppendLine("\tPath: The name of the registry key. Must be a subkey of the Hive specified. If not specific, the default key will be used.");
                sb.AppendLine("\tValue: The name of the registry value to be modified in the specified key. If it is not specified, the default (unnamed) value will be used.");
                sb.AppendLine("\tToWrite: The data to be written to the registry.");
                sb.AppendLine("\tNote: If toWrite is binary data, it must be Base64 encoded beforehand.");
                sb.AppendLine("\tNote: If type is multristring, pass toWrite in multiple times for each string, i.e. toWrite=abc&toWrite=cdf  ");

                return sb.ToString();
            }
            if (!args.ContainsKey("type")) return "Error: Required parameter 'type' missing.";
            if (!args.ContainsKey("hive")) return "Error: Required parameter 'hive' missing.";
            if (!args.ContainsKey("toWrite")) return "Error: required parameter 'toWrite' missing.";
            string type = args["type"][0]; //do stuff here
            string hive = args["hive"][0];
            if (!hives.Contains(hive.ToUpper()))
                return "Invalid hive name! Must be one of : 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_PERFORMANCE_DATA', 'HKEY_CURRENT_CONFIG' , or their appropriate shortcut ('hkcr', 'hkcu', etc).";
            string path;
            if (!args.ContainsKey("path"))
                path = "";
            else
                path = args["path"][0];
            string value;
            if (!args.ContainsKey("value"))
                value = "";
            else
                value = args["value"][0];
            if (type == "binary")
            {
                string b64 = args["toWrite"][0];
                byte[] decoded = Convert.FromBase64String(b64);
                return libPhate.WriteBinary(hive, path, value, decoded);
            }
            if (type == "dword")
            {
                UInt32 dword;
                if (false == UInt32.TryParse(args["toWrite"][0], out dword))
                    return "Error parsing value toWrite into uint32";
                return libPhate.WriteDWORD(hive, path, value, dword);
            }
            if (type == "qword")
            {
                UInt64 qword;
                if (false == UInt64.TryParse(args["toWrite"][0], out qword))
                    return "Error parsing value toWrite into uint64";
                return libPhate.WriteQWORD(hive, path, value, qword);
            }
            if (type == "string")
                return libPhate.WriteString(hive, path, value, args["toWrite"][0]);
            if (type == "multistring")
            {
                string[] arr = args["toWrite"].ToArray();
                return libPhate.WriteMultiString(hive, path, value, arr);
            }
            return "Invalid type! Try again";
        }



        private string _do_whoami(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("whoami: Returns user identity information.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tflags={value}: Flags to control output. Default is 0 (Just show user's name).");
                sb.AppendLine("\tValid flags are:");
                sb.AppendLine("\t\t1 = User Group Membership");
                sb.AppendLine("\t\t2 = User Privileges");

                return sb.ToString();
            }

            int flags = 0;
            string output = "";

            if (args.ContainsKey("flags"))
                if (false == Int32.TryParse(args["flags"][0], out flags))
                {
                    flags = 0;
                    output += "Warning: Unable to parse flags parameter." + Environment.NewLine;
                }

            output += libPhate.PrintCurrentUserInfo(flags);

            return output; 
        }


        private string _do_chown(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("chown: Changes ownership on an object.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tname: the name of the object to change ownership of");
                sb.AppendLine("\ttype: the type of object you are changing ownership of. See MSDN for more info on SE_OBJECT_TYPE");
                sb.AppendLine("\t\t hints: SE_FILE_OBJECT is 1, SE_REGISTRY_KEY is 4, see MSDN for the rest");
                sb.AppendLine("\towner: the account name of the new owner");
                return sb.ToString();
            }
            if (!args.ContainsKey("name"))
                return "missing required argument 'name'";
            if (!args.ContainsKey("type"))
                return "missing required argument 'type'";
            string owner;
            if (!args.ContainsKey("owner"))
                owner = "";
            else
                owner = args["owner"][0];


            int type;
            if(false == Int32.TryParse(args["type"][0], out type)){
                return "unable to parse type parameter. it should be a non-negative number";
            }

            return libPhate.ChangeOwner(args["name"][0], type, owner);
        }

        private string _do_chgroup(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("chown: Changes ownership on an object.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tname: the name of the object to change group of");
                sb.AppendLine("\ttype: the type of object you are changing group of. See MSDN for more info on SE_OBJECT_TYPE");
                sb.AppendLine("\t\t hints: SE_FILE_OBJECT is 1, SE_REGISTRY_KEY is 4, see MSDN for the rest");
                sb.AppendLine("\tgroup: the name of the new group");
                return sb.ToString();
            }
            if (!args.ContainsKey("name"))
                return "missing required argument 'name'";
            if (!args.ContainsKey("type"))
                return "missing required argument 'type'";
            if (!args.ContainsKey("group"))
                return "missing required argument 'group'";
            


            int type;
            if (false == Int32.TryParse(args["type"][0], out type))
            {
                return "unable to parse type parameter. it should be a non-negative number";
            }

            return libPhate.ChangeGroup(args["name"][0], type, args["group"][0]);
        }


        private string _do_chmod(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("chown: Changes ownership on an object.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tname: the name of the object to change group of");
                sb.AppendLine("\ttype: the type of object you are changing group of. See MSDN for more info on SE_OBJECT_TYPE");
                sb.AppendLine("\t\t hints: SE_FILE_OBJECT is 1, SE_REGISTRY_KEY is 4, see MSDN for the rest");
                sb.AppendLine("\tperms: the permissions to set. some combination of: \r\n\t\t 'r' = GENERIC_READ \r\n\t\t 'w' = GENERIC_WRITE \r\n\t\t 'x' = GENERIC_EXECUTE \r\n\t\t '*' == GENERIC_ALL \r\n\t\t 'd' = DELETE \r\n\t\t 'c' = READ_CONTROL \r\n\t\t 'a' = WRITE_DAC \r\n\t\t 'o' = WRITE_OWNER \r\n\t\t 's' = SYNCHRONIZE");


                return sb.ToString();
            }
            if (!args.ContainsKey("name"))
                return "missing required argument 'name'";
            if (!args.ContainsKey("type"))
                return "missing required argument 'type'";
            if (!args.ContainsKey("perms"))
                return "missing required argument 'group'";

            string perms = args["perms"][0].ToLower();
            if (!perms.Contains("r") && !perms.Contains("w") && !perms.Contains("x") && !perms.Contains("x") && !perms.Contains("*") && !perms.Contains("d") && !perms.Contains("c") && !perms.Contains("a") && !perms.Contains("o") && !perms.Contains("s"))
                return "invalid perms string ";


            int type;
            if (false == Int32.TryParse(args["type"][0], out type))
            {
                return "unable to parse type parameter. it should be a non-negative number";
            }

            return libPhate.ChangePerms(args["name"][0], type, perms);
        }




        private string _do_cat(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("cat: Echos file contents to the output stream");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tfile={value}: File to display. Required.");
                sb.AppendLine("\twrap={value}: Column to wrap the output at.  Default is no wrapping.");

                return sb.ToString();
            }

            if (args.ContainsKey("file") == false)
                return "Error: Required parameter, file={value}, missing.";

            string file = args["file"][0];
            uint linewrap = 0;
            string output = "";
            
            if (args.ContainsKey("wrap")) // wrap to column
                if (false == uint.TryParse(args["wrap"][0], out linewrap))
                {
                    output += "Warning: Unable to parse wrap parameter.\n";
                    linewrap = 0;
                }

            output += libPhate.ReadFile(file, linewrap);

            return output;
            
        }

        private List<KeyValuePair<int, ulong>> burn_tracker = new List<KeyValuePair<int, UInt64>>();

        private string _do_burn(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("burn: Consumes resources to test low resource conditions.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tmem_pages={value}. The number of pages (not bytes) of memory to allocate.");
                sb.AppendLine("\tstop: Frees any resources consumed.");
                sb.AppendLine("");
                sb.AppendLine("Either mem_pages or stop must be provided.");

                return sb.ToString();
            }

            if (args.ContainsKey("stop") == false && args.ContainsKey("mem_pages") == false)
                return "Error: Required parameter missing.";

            if (args.ContainsKey("stop"))
            {
                foreach (KeyValuePair<int, UInt64> kvp in burn_tracker)
                {
                    libPhate.BurnFree(kvp.Key, kvp.Value);
                }

                burn_tracker.Clear();

                return "Info: Resources Freed";
            }
            else if (args.ContainsKey("mem_pages"))
            {
                uint pagecount = 0;

                uint.TryParse(args["mem_pages"][0], out pagecount);

                if (pagecount > 0)
                {
                    UInt64 retval = libPhate.Burn(0x1 /*mem*/, pagecount);

                    if (retval > 0)
                    {
                        KeyValuePair<int, UInt64> kvp = new KeyValuePair<int, UInt64>(0x1, retval);

                        burn_tracker.Add(kvp);

                        return "Info: " + pagecount.ToString() + " pages allocated successfully";

                    }
                    else
                        return "Error: Unable to allocate the requested amount of pages. Returned value was " + retval.ToString();
                }
                else
                    return "Error: Unable to parse pagecount";
            } // mem_pages

            else
                return "Error: Impossible code path";

            

        }

        private string _do_handles(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("handles: Displays the handle table for a process.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tpid={value}. The process to enumerate the handle table of. ");
                sb.AppendLine("\tflags={value}. Flags that control the output. Default is 0 (display all handles) ");
                sb.AppendLine("\tFlag bits:");
                sb.AppendLine("\t\t1 - Only display handles to named objects.");
                sb.AppendLine("\t\t2 - Parse and display the granted access for the handles (Not Yet Implemented).");
                sb.AppendLine("");
                sb.AppendLine("If no pid is specified, this command will display all the handles for all processes.");
                sb.AppendLine("Note that no information can be displayed for handles in other processes at the moment, because this application");
                sb.AppendLine("lacks the privileges necessary to duplicate the handle into this process (for the most part).");

                return sb.ToString();
            }

            // Shoehorning in a flags value in the low bits of the pid 
            // since all pids are going to be multiples of 4 or 8 (dep. on system)
            string retval = "";

            uint pid = 0;
            uint flags = 0;

            if (args.ContainsKey("flags"))
            {
                if (uint.TryParse(args["flags"][0], out flags) == false)
                {
                    flags = 0;
                    retval += "Warning: Unable to parse flags value\n";
                }
                else
                {
                    flags = flags & 0x03; // only two bits guaranteed available
                }
            }

            if (args.ContainsKey("pid"))
            {
                if (uint.TryParse(args["pid"][0], out pid) == false)
                {
                    pid = 0;
                    retval += "Warning: Unable to parse pid value\n";
                }
            }

            retval +=  libPhate.EnumerateHandles((pid | flags).ToString());

            return retval;

        }

        private string _do_launch(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("launch: Launches a URL or file to another application. For testing URI or File Associations in other applications.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\turi={value}. The URI that is handled by another application.");
                sb.AppendLine("\tfile={value}. The file that is handled by another application. It must already exist in the application local directory.");
                sb.AppendLine("");
                sb.AppendLine("Either uri or file must be specified.");
                sb.AppendLine("This command will activate the other application, putting this application into the background");
                sb.AppendLine("until the other application is terminated.");

                return sb.ToString();
            }

            if (!args.ContainsKey("uri") && !args.ContainsKey("file"))
                return "Error: Missing required parameter. Please specify either uri={value} or file={value}";

            if (args.ContainsKey("uri"))
                return libPhate.LaunchUri(args["uri"][0]);
            else
                return libPhate.LaunchFile(args["file"][0]);
        }

        private string _do_mitigations(StreamSocket s, Dictionary<string, List<string>> args)
        {
            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("mit: Enumerates the mitigations enabled for a process.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tpid={value}. The process id to enumerate. Required.");
                sb.AppendLine("");
                sb.AppendLine("Note that no information can be displayed for other processes at the moment, because this application");
                sb.AppendLine("lacks the privileges necessary to other processes (for the most part).");

                return sb.ToString();
            }

            if(args.ContainsKey("pid"))
                return libPhate.ProcessMitigationInfo(args["pid"][0]);

            return "Error: Required parameter, pid={value}, missing.";
        }

        private string _do_memory(StreamSocket s, Dictionary<string, List<string>> args)
        {

            if (args.ContainsKey("help"))
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("mem: Displays the memory map for a process.");
                sb.AppendLine("");
                sb.AppendLine("Parameters");
                sb.AppendLine("\tpid={value}. The process id to enumerate. Required.");
                sb.AppendLine("");
                sb.AppendLine("Note that no information can be displayed for other processes at the moment, because this application");
                sb.AppendLine("lacks the privileges necessary to other processes (for the most part).");

                return sb.ToString();
            }

            if (args.ContainsKey("pid"))
                return libPhate.MemoryRegions(args["pid"][0]);

            return "Error: Required parameter, pid={value}, missing.";
        }

        #endregion
    }
}
