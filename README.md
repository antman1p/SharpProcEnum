# SharpProcEnum
.NET tool for enumeration processes and dumping memory.

This program allows to user to list PIDs and names of processes, thread TIDs and Base addresses for threads of a desired process,
module names and base addresses for loaded modules of a desired process, check the protection level of a memory page for a process module,
and to dump the memory of a desired memory page of a process in "Hex Dump" format.

Usage:
 -proclist            Lists running processes on the system
 -threadlist <pid>    Lists threads running on a given preocess
 -modlist <pid>       Lists loaded modules and their addresses for a given process
 -meminfo <pid> <Base Address>  Output the memory access protection level for a given module page
 -memdump <pid> <Base Address>  Outputs the memory of a given module page
 -help                Prints this usage page
