using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading;

namespace DiskExpander
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct DiskGeometry
    {
        public long Cylinders;
        public int MediaType;
        public int TracksPerCylinder;
        public int SectorsPerTrack;
        public int BytesPerSector;
    }

    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                var name = "\\\\.\\C:";
                var handle = DriveLayout.NativeMethods.CreateFile(name,
                    DriveLayout.NativeMethods.AccessRights.GENERIC_READ |
                    DriveLayout.NativeMethods.AccessRights.GENERIC_WRITE, FileShare.Read | FileShare.Write, IntPtr.Zero,
                    DriveLayout.NativeMethods.FileCreationDisposition.OPEN_EXISTING, FileAttributes.Normal,
                    IntPtr.Zero);
                
                var geo = GetDiskGeometry(handle);
                ExpandPartition(handle, geo);
                handle.Close();
                //Console.WriteLine("Closed: " + handle.IsClosed);
                Console.WriteLine((Int64)geo.TracksPerCylinder * (Int64)geo.SectorsPerTrack * (Int64)geo.Cylinders);
                handle.Dispose();
            }
            else
            {
                var sectors = Convert.ToInt64(args[0]);
                ExpandDrive(sectors);
            }
            
            
        }

        private static void ExpandPartition(DriveLayout.FileSafeHandle handle, DiskGeometry geometry)
        {
            var li = new DriveLayout.NativeMethods.DRIVE_LAYOUT_INFORMATION_EX
            {
                PartitionCount = DriveLayout.NativeMethods.PartitionEntriesCount,
                PartitionEntry = new DriveLayout.NativeMethods.PARTITION_INFORMATION_EX[DriveLayout.NativeMethods.PartitionEntriesCount]
            };
            int bytesReturned1 = 0;

            DriveLayout.NativeMethods.DeviceIoControl(
                handle,
                DriveLayout.NativeMethods.IoControlCode.IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                IntPtr.Zero,
                0,
                ref li,
                Marshal.SizeOf(li),
                ref bytesReturned1,
                IntPtr.Zero
            );

            Console.WriteLine("Current Parittion 0 to size " + li.PartitionEntry[0].PartitionLength);
            Console.WriteLine("Starting Offset: " + li.PartitionEntry[0].StartingOffset);
            var SizeToBe = ((long) geometry.TracksPerCylinder * (long) geometry.SectorsPerTrack * (long) geometry.BytesPerSector * geometry.Cylinders) - li.PartitionEntry[0].StartingOffset;
            if (SizeToBe == li.PartitionEntry[0].PartitionLength)
            {
                Console.WriteLine("Size is at maxcap");
            }
            else
            {
                li.PartitionEntry[0].PartitionLength = SizeToBe;
                Console.WriteLine("Expanding Parittion 0 to size " + li.PartitionEntry[0].PartitionLength);

                bool outp = false;
                ExecuteNativeActionAndCheckLastError(() =>
                {

                    outp = DriveLayout.NativeMethods.DeviceIoControl(
                        handle,
                        DriveLayout.NativeMethods.IoControlCode.IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
                        ref li,
                        Marshal.SizeOf(li),
                        IntPtr.Zero,
                        0,
                        ref bytesReturned1,
                        IntPtr.Zero
                    );
                });
                Console.WriteLine("Success: " + outp);
            }
            
            Console.WriteLine("Sectors: " + (li.PartitionEntry[0].PartitionLength / geometry.BytesPerSector) );
            Console.WriteLine("Recommended sectors = " +(li.PartitionEntry[0].PartitionLength - li.PartitionEntry[0].StartingOffset) / geometry.BytesPerSector);
        }

        private static void ExpandDrive(long sectors)
        {
            var name = "\\\\.\\C:";
            var handle = DriveLayout.NativeMethods.CreateFile(name,
                DriveLayout.NativeMethods.AccessRights.GENERIC_READ |
                DriveLayout.NativeMethods.AccessRights.GENERIC_WRITE, FileShare.Read | FileShare.Write, IntPtr.Zero,
                DriveLayout.NativeMethods.FileCreationDisposition.OPEN_EXISTING, FileAttributes.Normal, IntPtr.Zero);
            //var name = "\\\\?\\Volume{eac37c7e-1a14-11e7-bfc1-806e6f6e6963}\\";
            /*var handle = DriveLayout.NativeMethods.CreateFile(name,
                DriveLayout.NativeMethods.AccessRights.GENERIC_READ |
                DriveLayout.NativeMethods.AccessRights.GENERIC_WRITE, FileShare.Read | FileShare.Write, IntPtr.Zero,
                DriveLayout.NativeMethods.FileCreationDisposition.OPEN_EXISTING, FileAttributes.Normal, IntPtr.Zero);*/

            uint uintout = 0;
                int bytesReturned1 = 0;
                ExecuteNativeActionAndCheckLastError(() =>
                {
                    unsafe
                    {
                        //Int64 l = (Int64)geometry.TracksPerCylinder * (Int64)geometry.SectorsPerTrack * (Int64)geometry.Cylinders;
                        //Int64 l = 900000000;
                        Int64 l = sectors;
                        Int64* ptr = &l;
                        IntPtr addr = (IntPtr)ptr;
                        int vaoutp = DriveLayout.NativeMethods.DeviceIoControl(
                            handle,
                            DriveLayout.NativeMethods.IoControlCode.FsctlExtendVolume,
                            addr,
                            8,
                            IntPtr.Zero,
                            (uint)0,
                            bytesReturned1,
                            IntPtr.Zero
                        );
                        Console.WriteLine(vaoutp);
                    }

                });

            
        }

        private static DiskGeometry GetDiskGeometry(DriveLayout.FileSafeHandle handle)
        {
            var name = "\\\\.\\C:";
//            var handle = DriveLayout.NativeMethods.CreateFile(name, DriveLayout.NativeMethods.AccessRights.GENERIC_READ | DriveLayout.NativeMethods.AccessRights.GENERIC_WRITE, FileShare.Read | FileShare.Write, IntPtr.Zero, DriveLayout.NativeMethods.FileCreationDisposition.OPEN_EXISTING, FileAttributes.Normal, IntPtr.Zero)
            
                int geometrySize = Marshal.SizeOf(typeof(DiskGeometry));
                //Console.WriteLine("geometry size = {0}", geometrySize);

                IntPtr geometryBlob = Marshal.AllocHGlobal(geometrySize);
                uint numBytesRead = 0;


                DriveLayout.NativeMethods.DeviceIoControl(
                    handle,
                    DriveLayout.NativeMethods.IoControlCode.IoCtlDiskGetDriveGeometry,
                    IntPtr.Zero,
                    0,
                    geometryBlob,
                    (uint)geometrySize,
                    ref numBytesRead,
                    IntPtr.Zero
                );


                DiskGeometry geometry = (DiskGeometry)Marshal.PtrToStructure(geometryBlob, typeof(DiskGeometry));
                Marshal.FreeHGlobal(geometryBlob);
                Console.WriteLine("Cylinders: " + geometry.Cylinders);
                Console.WriteLine("SectorsPerTrack: " + geometry.SectorsPerTrack);
                Console.WriteLine("TracksPerCylinder: " + geometry.TracksPerCylinder);
                Console.WriteLine("BytesPerSector: " + geometry.BytesPerSector);
                return geometry;
            
        }

        private static void ExecuteNativeActionAndCheckLastError(Action action)
        {
            action();

            var lastError = Marshal.GetLastWin32Error();

            if (lastError != DriveLayout.NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception(lastError);
            }
        }
    }

    public class DriveLayout : IDisposable
    {


        private FileSafeHandle handle;


        public DriveLayout(string diskName)
        {
            ExecuteNativeActionAndCheckLastError(() =>
            {
                handle = NativeMethods.CreateFile(
                    diskName,
                    NativeMethods.AccessRights.GENERIC_READ,
                    0, IntPtr.Zero,
                    NativeMethods.FileCreationDisposition.OPEN_EXISTING,
                    0, IntPtr.Zero
                );
            });
        }

        public void SetDiskId(Guid newId)
        {
            int bytesReturned;
            var li = DriveLayoutInformationEx(out bytesReturned);

            if (li.PartitionStyle != NativeMethods.PARTITION_STYLE.PARTITION_STYLE_GPT)
            {
                throw new InvalidOperationException(string.Format("The specified drive should be GPT disk. Its current partition style is: {0}", li.PartitionStyle));
            }

            li.DriveLayoutInformation.Gpt.DiskId = newId;

            ExecuteNativeActionAndCheckLastError(() =>
            {
                NativeMethods.DeviceIoControl(
                    handle,
                    NativeMethods.IoControlCode.IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
                    ref li,
                    Marshal.SizeOf(li),
                    IntPtr.Zero,
                    0,
                    ref bytesReturned,
                    IntPtr.Zero
                );
            });

            //logger.Info("Disk ID = {0}", newId);
        }

        public NativeMethods.DRIVE_LAYOUT_INFORMATION_EX DriveLayoutInformationEx(out int bytesReturned)
        {
            var li = new NativeMethods.DRIVE_LAYOUT_INFORMATION_EX
            {
                PartitionCount = NativeMethods.PartitionEntriesCount,
                PartitionEntry = new NativeMethods.PARTITION_INFORMATION_EX[NativeMethods.PartitionEntriesCount]
            };
            var bytesReturned1 = 0;

            ExecuteNativeActionAndCheckLastError(() =>
            {
                NativeMethods.DeviceIoControl(
                    handle,
                    NativeMethods.IoControlCode.IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                    IntPtr.Zero,
                    0,
                    ref li,
                    Marshal.SizeOf(li),
                    ref bytesReturned1,
                    IntPtr.Zero
                );
            });
            bytesReturned = bytesReturned1;
            return li;
        }

        public void Dispose()
        {
            if (!handle.IsInvalid)
            {
                handle.Dispose();
            }
        }


        private void ExecuteNativeActionAndCheckLastError(Action action)
        {
            action();

            var lastError = Marshal.GetLastWin32Error();

            if (lastError != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception(lastError);
            }
        }


        public class NativeMethods
        {
            public enum AccessRights : uint
            {
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000
            }

            public enum FileCreationDisposition
            {
                CREATE_ALWAYS = 2,
                CREATE_NEW = 1,
                OPEN_ALWAYS = 4,
                OPEN_EXISTING = 3,
                TRUNCATE_EXISTING = 5
            }
            [Flags]
            public enum EMethod : uint
            {
                Buffered = 0,
                InDirect = 1,
                OutDirect = 2,
                Neither = 3
            }

            [Flags]
            public enum EFileDevice : uint
            {
                Beep = 0x00000001,
                CDRom = 0x00000002,
                CDRomFileSytem = 0x00000003,
                Controller = 0x00000004,
                Datalink = 0x00000005,
                Dfs = 0x00000006,
                Disk = 0x00000007,
                DiskFileSystem = 0x00000008,
                FileSystem = 0x00000009,
                InPortPort = 0x0000000a,
                Keyboard = 0x0000000b,
                Mailslot = 0x0000000c,
                MidiIn = 0x0000000d,
                MidiOut = 0x0000000e,
                Mouse = 0x0000000f,
                MultiUncProvider = 0x00000010,
                NamedPipe = 0x00000011,
                Network = 0x00000012,
                NetworkBrowser = 0x00000013,
                NetworkFileSystem = 0x00000014,
                Null = 0x00000015,
                ParallelPort = 0x00000016,
                PhysicalNetcard = 0x00000017,
                Printer = 0x00000018,
                Scanner = 0x00000019,
                SerialMousePort = 0x0000001a,
                SerialPort = 0x0000001b,
                Screen = 0x0000001c,
                Sound = 0x0000001d,
                Streams = 0x0000001e,
                Tape = 0x0000001f,
                TapeFileSystem = 0x00000020,
                Transport = 0x00000021,
                Unknown = 0x00000022,
                Video = 0x00000023,
                VirtualDisk = 0x00000024,
                WaveIn = 0x00000025,
                WaveOut = 0x00000026,
                Port8042 = 0x00000027,
                NetworkRedirector = 0x00000028,
                Battery = 0x00000029,
                BusExtender = 0x0000002a,
                Modem = 0x0000002b,
                Vdm = 0x0000002c,
                MassStorage = 0x0000002d,
                Smb = 0x0000002e,
                Ks = 0x0000002f,
                Changer = 0x00000030,
                Smartcard = 0x00000031,
                Acpi = 0x00000032,
                Dvd = 0x00000033,
                FullscreenVideo = 0x00000034,
                DfsFileSystem = 0x00000035,
                DfsVolume = 0x00000036,
                Serenum = 0x00000037,
                Termsrv = 0x00000038,
                Ksec = 0x00000039,
                // From Windows Driver Kit 7
                Fips = 0x0000003A,
                Infiniband = 0x0000003B,
                Vmbus = 0x0000003E,
                CryptProvider = 0x0000003F,
                Wpd = 0x00000040,
                Bluetooth = 0x00000041,
                MtComposite = 0x00000042,
                MtTransport = 0x00000043,
                Biometric = 0x00000044,
                Pmi = 0x00000045
            }
            public enum IoControlCode : uint
            {
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x70050,
                IOCTL_DISK_SET_DRIVE_LAYOUT_EX = 0x7c054,
                IoCtlDiskGetDriveGeometry = 0x70000,
                FsctlExtendVolume = (EFileDevice.FileSystem << 16) | (60 << 2) | EMethod.Buffered | (0 << 14),
            }

            public const Int32 ERROR_SUCCESS = 0;

            public const int PartitionEntriesCount = 10;

            public struct DRIVE_LAYOUT_INFORMATION_EX
            {
                public PARTITION_STYLE PartitionStyle;
                public Int32 PartitionCount;
                public DriveLayoutInformationUnion DriveLayoutInformation;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = PartitionEntriesCount)]
                public PARTITION_INFORMATION_EX[] PartitionEntry;
            }

            public enum PARTITION_STYLE : int
            {
                PARTITION_STYLE_MBR = 0,
                PARTITION_STYLE_GPT = 1,
                PARTITION_STYLE_RAW = 2
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct DriveLayoutInformationUnion
            {
                [FieldOffset(0)]
                public DRIVE_LAYOUT_INFORMATION_MBR Mbr;
                [FieldOffset(0)]
                public DRIVE_LAYOUT_INFORMATION_GPT Gpt;
            }

            public struct DRIVE_LAYOUT_INFORMATION_MBR
            {
                public UInt64 Signature;
            }

            public struct DRIVE_LAYOUT_INFORMATION_GPT
            {
                public Guid DiskId;
                public Int64 StartingUsableOffset;
                public Int64 UsableLength;
                public UInt32 MaxPartitionCount;
            }

            public struct PARTITION_INFORMATION_EX
            {
                public PARTITION_STYLE PartitionStyle;
                public Int64 StartingOffset;
                public Int64 PartitionLength;
                public UInt32 PartitionNumber;
                [MarshalAs(UnmanagedType.Bool)]
                public bool RewritePartition;
                public PartitionInformationUnion PartitionInformation;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct PartitionInformationUnion
            {
                [FieldOffset(0)]
                public PARTITION_INFORMATION_MBR Mbr;
                [FieldOffset(0)]
                public DRIVE_LAYOUT_INFORMATION_GPT Gpt;
            }

            public struct PARTITION_INFORMATION_MBR
            {
                public byte PartitionType;
                [MarshalAs(UnmanagedType.Bool)]
                public bool BootIndicator;
                [MarshalAs(UnmanagedType.Bool)]
                public bool RecognizedPartition;
                UInt32 HiddenSectors;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            struct PARTITION_INFORMATION_GPT
            {
                public Guid PartitionType;
                public Guid PartitionId;
                public UInt64 Attributes;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 36)]
                public string Name;
            }

            [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true)]
            public static extern FileSafeHandle CreateFile(
                [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
                AccessRights dwDesiredAccess,
                [MarshalAs(UnmanagedType.U4)] FileShare share,
                IntPtr lpSecurityAttributes,
                FileCreationDisposition dwCreationDisposition,
                [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
                IntPtr hTemplateFile
            );

            [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern Boolean DeviceIoControl(
                FileSafeHandle hDevice,
                IoControlCode dwIoControlCode,
                IntPtr lpInBuffer,
                int nInBufferSize,
                ref DRIVE_LAYOUT_INFORMATION_EX lpOutBuffer,
                Int32 nOutBufferSize,
                ref Int32 lpBytesReturned,
                IntPtr lpOverlapped
            );

            [DllImport("Kernel32.dll", SetLastError = false, CharSet = CharSet.Auto)]
            public static extern int DeviceIoControl(
                FileSafeHandle device,
                IoControlCode dwIoControlCode,
                IntPtr inBuffer,
                uint inBufferSize,
                IntPtr outBuffer,
                uint outBufferSize,
                ref Int32 bytesReturned,
                IntPtr overlapped
            );
            [DllImport("Kernel32.dll", SetLastError = false, CharSet = CharSet.Auto)]
            public static extern int DeviceIoControl(
                FileSafeHandle device,
                IoControlCode dwIoControlCode,
                IntPtr inBuffer,
                uint inBufferSize,
                IntPtr outBuffer,
                uint outBufferSize,
                Int32 bytesReturned,
                IntPtr overlapped
            );
            [DllImport("Kernel32.dll", SetLastError = false, CharSet = CharSet.Auto)]
            public static extern int DeviceIoControl(
                FileSafeHandle device,
                IoControlCode dwIoControlCode,
                IntPtr inBuffer,
                int inBufferSize,
                IntPtr outBuffer,
                uint outBufferSize,
                ref uint bytesReturned,
                IntPtr overlapped
            );

            [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern Boolean DeviceIoControl(
                FileSafeHandle hDevice,
                IoControlCode dwIoControlCode,
                ref DRIVE_LAYOUT_INFORMATION_EX lpInBuffer,
                int nInBufferSize,
                IntPtr lpOutBuffer,
                Int32 nOutBufferSize,
                ref Int32 lpBytesReturned,
                IntPtr lpOverlapped
            );
        }


        [SecurityPermission(SecurityAction.Demand)]
        public class FileSafeHandle : BaseSafeHandle { }
        [SecurityPermission(SecurityAction.Demand)]
        public class BaseSafeHandle : SafeHandle
        {

            public BaseSafeHandle()
                : base(IntPtr.Zero, true)
            { }


            public override bool IsInvalid
            {
                get { return (this.IsClosed) || (base.handle == IntPtr.Zero); }
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(this.handle);
            }

            public override string ToString()
            {
                return this.handle.ToString();
            }

            /// <summary>
            /// Closes an open object handle.
            /// </summary>
            /// <param name="hObject">A valid handle to an open object.</param>
            /// <returns>If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To get extended error information, call GetLastError.</returns>
            [DllImportAttribute("kernel32.dll", SetLastError = true)]
            [return: MarshalAsAttribute(UnmanagedType.Bool)]
            protected static extern Boolean CloseHandle(IntPtr hObject);
        }
    }
}
