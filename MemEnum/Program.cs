/*
 * SharpProcEnum
 * By: Antonio Piazza 4n7m4n
 * Twitter @antman1p
 * 2/12/2019
 * 
 *  Program in C# that:
 *
 * 1.  List all running processes.
 * 2.  List all  running threads within a selected process boundary.
 * 3.  Enumerate all the loaded modules within the processes.
 * 4.  Show all the executable pages within the processes.
 * 5.  Read  memory.
 *
 *
 * 
 * References: https://stackoverflow.com/questions/648410/how-can-i-list-all-processes-running-in-windows
 *             https://stackoverflow.com/questions/10315862/get-list-of-threads
 *             https://stackoverflow.com/questions/36431220/getting-a-list-of-dlls-currently-loaded-in-a-process-c-sharp
 *             https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process?redirectedfrom=MSDN&view=netframework-4.7.2
 *             https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.getprocessbyid?view=netframework-4.7.2
 *             https://www.pinvoke.net/default.aspx/kernel32.openprocess
 *             https://www.pinvoke.net/default.aspx/psapi.enumprocessmodules
 *             https://www.pinvoke.net/default.aspx/psapi.getmodulefilenameex
 *             https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-enumprocessmodules
 *             https://www.codeproject.com/Articles/716227/Csharp-How-to-Scan-a-Process-Memory
 *             https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants
 *             https://docs.microsoft.com/en-us/windows/desktop/debug/system-error-codes--0-499-
 *             https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_memory_basic_information
 *             
 *             HIGHLY influenced by Matt Graeber's (@mattifestation) Powershell Arsenal MemoryTools.ps1
 *             https://github.com/mattifestation/PowerShellArsenal/blob/master/MemoryTools/MemoryTools.ps1
 * 
 * 
 * INSTRUCTIONS:  Use a 64 bit WIndows system.  For BEST results, run as an administrator.  Build using visual studio.
*/



using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace SharpProcEnum
{
    class Program
    {
        //Main FUnction looks at commandline args and calls the coresponding funciton
        static void Main(string[] args)
        {
            if(args.Length != 0){
                string selection = args[0];
                switch (selection) {
                    case "-proclist":
                        ProcList();
                        break;
                    case "-threadlist":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("\nNot enough arguments entered.");
                            help();
                        }
                        else
                        {
                            ThreadList(args[1]);
                        }
                        break;
                    case "-modlist":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("\nNot enough arguments entered.");
                            help();
                        }
                        else
                        {
                            ModList(args[1]);
                        }
                        break;
                    case "-meminfo":
                        if (args.Length < 3)
                        {
                            Console.WriteLine("\nNot enough arguments entered.");
                            help();
                        }
                        else
                        {
                            MemInfo(args[1], args[2]);
                        }
                        break;                      
                    case "-memdump":
                        if (args.Length < 3)
                        {
                            Console.WriteLine("\nNot enough arguments entered.");
                            help();
                        }
                        else
                        {
                            MemDump(args[1], args[2]);
                        }
                        break;
                        
                    case "-help":
                        help();
                        break;        
                    default:
                        Console.WriteLine(args[0] + " not a valid option. For help use the -help option\n");
                        help();
                        break;
                }
            }
            else
                {
                    help();
                }
            Console.ReadLine();

        }

        // The Menu function displays the menu to the console and takes user input to call the corresponding function
        public static void help()
        {

            // Write Menu to console
            Console.WriteLine("\nUsage: MemEnum.exe [options]\n" +
                "\n-proclist\t\t\tLists running processes on the system" +
                "\n-threadlist <pid>\t\tLists threads running on a given preocess" +
                "\n-modlist <pid>\t\t\tLists loaded modules and their addresses for a given process" +
                "\n-meminfo <pid> <Base Address>\tOutput the memory access protection level for a given module page" +
                "\n-memdump <pid> <Base Address>\tOutputs the memory of a given module page" +
                "\n-help\t\t\t\tPrints this usage page" +
                "\n");
        }

        // Function to list the processes
        public static void ProcList()
        {
            Process[] proclist = Process.GetProcesses();
            // List each of the the processes to console
            foreach (Process process in proclist)
            {
                // Print the proc ID and Name
                Console.WriteLine("\nProcess: {0} PID: {1}", process.ProcessName, process.Id);
            }
        }


        // Function to list the threads of a process by PID
        public static void ThreadList(string pidString)
        {
            int pid;

            // Check to make sure the input is an integer
            try
            {
                pid = Convert.ToInt32(pidString);

            }
            // If not call the help() funciton to return to the menu
            catch (Exception ex)
            {
                Console.WriteLine("Input not an integer.  Please try again");
                help();
                pid = 0;
            }

            try
            {
                // Get the process object for the pid input
                Process proc = Process.GetProcessById(pid);

                // Get the collection of threads for the process
                ProcessThreadCollection threads = proc.Threads;

                // List the threads to console
                foreach (ProcessThread thread in threads)
                {
                    // List the thread start address in hex format, the thread state, and the thread's base priority
                    Console.WriteLine("TID: {0}  Start Address: 0x{1}  Thread State: {2}  Base Priority: {3}", thread.Id, thread.StartAddress.ToString("X"), thread.ThreadState, thread.BasePriority);

                }

            }
            // If it fails call the help() function to return to the menu and alert the user to the failure
            catch(Exception ex)
            {
                Console.WriteLine("No Process Found with that Process ID. \nError: {0}", ex);
                help();
            }
        }

        // Fucntion that lists the modules for a user selected process
        public static void ModList(string pidString)
        {
            int pid;

            // Ensure the input is an integer
            try
            {
                pid = Convert.ToInt32(pidString);

            }
            // If not got to the help and alert the user
            catch (Exception ex)
            {
                Console.WriteLine("Input not an integer.  Please try again");
                help();
                pid = 0;
            }

            try
            {
                // Get the process requested by the user pid input
                Process process = Process.GetProcessById(pid);
                ProcessModule procMod;

                // Get the module collection of the process
                ProcessModuleCollection processModuleColl = process.Modules;

                // For each module in the collection write the modules to console
                for ( int i =0; i < processModuleColl.Count; i++)
                {
                    procMod = processModuleColl[i];

                    // Write the module name and base address in hex
                    Console.WriteLine("File Name: {0}  Base Address: 0x{1}", procMod.FileName, procMod.BaseAddress.ToString("X"));
                }
            }
            // If it fails alert the user and go to the help
            catch(Exception ex)
            {
                Console.WriteLine("No Process Found with that Process ID. \nError: {0}", ex);
                help();
            }
        }


        // Function that checks the Access protection level of a memory location
        public static void MemInfo(string pidString, string memAddrStr)
        {
            int pid;
            uint pageSize = 0x1000;

            // ensure the input is an integer
            try
            {
                pid = Convert.ToInt32(pidString);

            }

            // If not, go back to the menu and alert the usre
            catch (Exception ex)
            {
                Console.WriteLine("Input not an integer.  Please try again");
                help();
                pid = 0;
            }

            // Ensure the pid is to a running process
            try
            {
                Process proc = Process.GetProcessById(pid);
            }
            // If not go to the help an dinform the user
            catch (Exception ex)
            {
                Console.WriteLine("Not a valid process. \nError: {0}", ex);
                help();
            }

            
            // ensure that the user entered a hex address
            try
            {
                Convert.ToInt64(memAddrStr, 16);
            }
            // If not alert the user and go to the help
            catch(Exception ex)
            {
                Console.WriteLine("Invalid Memory address format.  Must be in hex, 0x... format.  Error: {0}", ex);
                help();
            }

            // Create a new pointer from converting the user input string to a 64 bit integer 
            IntPtr base_mem_address = new IntPtr(Convert.ToInt64(memAddrStr, 16));


            try
            {
                // Create a new basic memory information instancefrom the struct created belwo
                MEMORY_BASIC_INFORMATION64 mem_basic_info = new MEMORY_BASIC_INFORMATION64();

                // Winsows APOI function callopening the process with desired access level and saving the handle to the process 
                IntPtr pHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, pid);

                // Windows API funciton call to query the process memory information and save the information in the basic information struct instance created above
                VirtualQueryEx(pHandle, base_mem_address, out mem_basic_info, pageSize);

                // Call the get Memory Constant String funciton and save it a s a string
                string memProtectConstStr = getMemProtectConstStr(mem_basic_info.Protect);

                // Write the Memory protection information string to the console 
                Console.WriteLine("\nProtection Information: {0}", memProtectConstStr);
            }
            // Or else go to the help and alert the user of the failure
            catch(Exception ex)
            {
                Console.WriteLine("\nFailed to Open memory location.  \nError: {0}", ex);
                help();
            }
        }


        // Function dumps the contents of the memory requested by  the user to console
        public static void MemDump(string pidString, string memAddrStr)
        {

            int buffWidth = 16;
            int pid;
            int offset = 0x1000;
            int bytesRead = 0;

            Int64 baseAddr;
            var byteArray = new byte[offset];

            // Ensure the input pid is an integer
            try
            {
                pid = Convert.ToInt32(pidString);

            }
            // If not go to the help and alert the user
            catch (Exception ex)
            {
                Console.WriteLine("\nInput not an integer.  Please try again");
                help();
                pid = 0;
            }

            // Ensure the pid is to a running process
            try
            {
                Process proc = Process.GetProcessById(pid);
            }
            // If not go to the help an dinform the user
            catch(Exception ex)
            {
                Console.WriteLine("Not a valid process. \nError: {0}", ex);
                help();
            }

            // Ensure the input is a memory address in hex
            try
            {
                Convert.ToInt64(memAddrStr, 16);
            }
            // if not go to the help and alert the user
            catch (Exception ex)
            {
                Console.WriteLine("\nInvalid Memory address format.  Must be in hex, 0x... format.  \nError: {0}", ex);
                help();
            }

            // Create a new pointer from converting the user input string to a 64 bit integer 
            IntPtr base_mem_address = new IntPtr(Convert.ToInt64(memAddrStr, 16));

            

            try
            {
                // Windows API fucntion call opening the process with desired access level and saving the handle to the process 
                IntPtr pHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, pid);

                // Windows API call fucntion to read the process memory into a byte array
                ReadProcessMemory(pHandle, base_mem_address, byteArray, offset, ref bytesRead);

            }
            // If it fails, go to help and alert the user
            catch(Exception ex)
            {
                Console.WriteLine("Unable to dump memory.  \nError: {0}", ex);
                help();
            }

            int position = 0;
            int padding = (buffWidth * 2) + buffWidth;

            Console.WriteLine("\n");

            // Loop to print the memory dump to the consol ein "Hex Dump" typre format
            while (position < offset)
            {
                string line = "";
                line = "0x" + position.ToString("X8") + " ";
                string printBytes = "";
                string text = "";

                for(int i = 0; i < (buffWidth-1); i++)
                {
                    if(position >= offset) { break; }

                    printBytes += byteArray[position].ToString("X2") + " ";

                    if (char.IsLetterOrDigit((char)byteArray[position]) || char.IsPunctuation((char)byteArray[position]) || char.IsSymbol((char)byteArray[position]))
                    {
                        text += (char)byteArray[position];
                    }   
                    else
                    {
                        text += '.';
                    }
                    position++;

                }
                line += printBytes.PadRight(padding, ' ');
                line += " " + text;
                Console.WriteLine(line);

            }
        }

        // Function Converts Memory Protection Constant to its coresponding string value:
        // https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants
        public static string getMemProtectConstStr(uint memProtectConst)
        {
            string memProtectConstStr;
            switch(memProtectConst)
            {
                case (10):
                    memProtectConstStr = "PAGE_EXECUTE"; break;
                case (20):
                    memProtectConstStr = "PAGE_EXECUTE_READ"; break;
                case (40):
                    memProtectConstStr = "PAGE_EXECUTE_READWRITE"; break;
                case (80):
                    memProtectConstStr = "PAGE_EXECUTE_WRITECOPY"; break;
                case (1):
                    memProtectConstStr = "PAGE_NOACCESS"; break;
                case (2):
                    memProtectConstStr = "PAGE_READONLY"; break;
                case (4):
                    memProtectConstStr = "PAGE_READWRITE"; break;
                case (8):
                    memProtectConstStr = "PAGE_WRITECOPY"; break;
                case (40000000):
                    memProtectConstStr = "PAGE_TARGETS_INVALID"; break;
                case (100):
                    memProtectConstStr = "PAGE_GUARD"; break;
                case (200):
                    memProtectConstStr = "PAGE_NOCACHE"; break;
                case (400):
                    memProtectConstStr = "PAGE_WRITECOMBINE"; break;
                default:
                    memProtectConstStr = "PAGE_NOACCESS";  break;
            }

            return memProtectConstStr;
        }


        // REQUIRED CONSTS
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;

        const int PAGE_READONLY = 0x02;
        const int PAGE_READWRITE = 0x04;
        const int PAGE_EXECUTE = 0x10;
        const int PAGE_EXECUTE_READ = 0x20;
        const int PAGE_EXECUTE_READWRITE = 0x40;
        const int PAGE_EXECUTE_WRITECOPY = 0x80;
       
        const int PROCESS_WM_READ = 0x0010;
       
        // REQUIRED METHODS
        //[DllImport("kernel32.dll")]
        //static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        //Windows API function to Query the memory infomration of a process
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        // Windows API funciton to read the process memory to a byte array
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        // Windows API funcition to open a process
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        // REQUIRED STRUCTS
        //public struct SYSTEM_INFO
        //{
        //    public ushort processorArchitecture;
        //    ushort reserved;
        //    public uint pageSize;
        //    public IntPtr minimumApplicationAddress;  // minimum address
        //    public IntPtr maximumApplicationAddress;  // maximum address
        //    public IntPtr activeProcessorMask;
        //    public uint numberOfProcessors;
        //    public uint processorType;
        //    public uint allocationGranularity;
        //    public ushort processorLevel;
        //    public ushort processorRevision;
        //}

        // Struc to hold basic memory information for a module
        public struct MEMORY_BASIC_INFORMATION64
        {
            public UInt64 BaseAddress;
            public UInt64 AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public UInt64 RegionSize;   // size of the region allocated by the program
            public uint State;   // check if allocated (MEM_COMMIT)
            public uint Protect; // page protection (must be PAGE_READWRITE)
            public uint Type;
            public uint __alignment2;
        }
    }
}
