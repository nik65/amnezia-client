using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class AmneziaServiceSnapshotNative
{
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ScManagerConnect = 0x0001;
    private const uint QueryServiceConfig2FailureActions = 2;
    private const uint QueryServiceConfig2DelayedAutoStart = 3;
    private const uint QueryServiceConfig2FailureActionsFlag = 4;
    private const int ScActionRestart = 1;
    private const int MaxBuffer = 8192;
    private const int MaxStringChars = 4096;
    private const int MaxDependencies = 256;

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenScManager(string machineName, string databaseName, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint access);
    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    private static extern bool QueryServiceConfig(IntPtr service, IntPtr config, uint size, out uint needed);
    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
    private static extern bool QueryServiceConfig2(IntPtr service, uint level, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigNative
    {
        public uint serviceType;
        public uint start;
        public uint errorControl;
        public IntPtr imagePath;
        public IntPtr loadOrderGroup;
        public uint tagId;
        public IntPtr dependencies;
        public IntPtr startName;
        public IntPtr displayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FailureActionsNative
    {
        public uint resetPeriod;
        public IntPtr rebootMessage;
        public IntPtr commandLine;
        public uint actionCount;
        public IntPtr actions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ScActionNative
    {
        public uint type;
        public uint delay;
    }

    public string name;
    public int serviceType;
    public int errorControl;
    public int start;
    public int delayedAutoStart;
    public string startName;
    public string imagePath;
    public string dependencies;
    public string failureActions;
    public uint failureResetPeriod;
    public int failureActionCount;
    public string failureActionTypes;
    public string failureActionDelays;
    public string rebootMessage;
    public string commandLine;
    public int failureActionsFlag;
    public string failureActionsFlagRaw;

    private static void Fail(string operation)
    {
        int code = Marshal.GetLastWin32Error();
        throw new Win32Exception(code, operation);
    }

    private static bool InRange(IntPtr pointer, long begin, long end, int bytes)
    {
        if (pointer == IntPtr.Zero || bytes < 0) return false;
        long value = pointer.ToInt64();
        return value >= begin && value <= end - bytes;
    }

    private static IntPtr PointerAt(IntPtr buffer, int offset, long begin, long end)
    {
        if (offset < 0 || offset > MaxBuffer || !InRange(buffer, begin, end, offset + IntPtr.Size))
            throw new InvalidOperationException("pointer-offset");
        return Marshal.ReadIntPtr(buffer, offset);
    }

    private static int FieldOffset(Type type, string field)
    {
        return Marshal.OffsetOf(type, field).ToInt32();
    }

    private static string ReadString(IntPtr pointer, long begin, long end, bool allowNull)
    {
        if (pointer == IntPtr.Zero)
        {
            if (allowNull) return "";
            throw new InvalidOperationException("null-string");
        }
        long value = pointer.ToInt64();
        if (value < begin || value >= end || ((value - begin) & 1) != 0)
            throw new InvalidOperationException("string-pointer");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < MaxStringChars; ++i)
        {
            IntPtr character = new IntPtr(checked(value + (long)i * 2));
            if (!InRange(character, begin, end, 2)) throw new InvalidOperationException("string-bounds");
            short code = Marshal.ReadInt16(character);
            if (code == 0) return result.ToString();
            result.Append((char)code);
        }
        throw new InvalidOperationException("string-too-long");
    }

    private static string ReadMultiSz(IntPtr pointer, long begin, long end)
    {
        if (pointer == IntPtr.Zero) return "";
        StringBuilder result = new StringBuilder();
        IntPtr current = pointer;
        for (int item = 0; item < MaxDependencies; ++item)
        {
            string value = ReadString(current, begin, end, false);
            if (value.Length == 0) return result.ToString();
            if (item > 0) result.Append(',');
            result.Append(value);
            current = new IntPtr(checked(current.ToInt64() + (long)(value.Length + 1) * 2));
        }
        throw new InvalidOperationException("dependencies-too-many");
    }

    private static IntPtr QueryBuffer(IntPtr service, uint level, out uint bufferSize)
    {
        uint needed = 0;
        QueryServiceConfig2(service, level, IntPtr.Zero, 0, out needed);
        if (needed == 0 || needed > MaxBuffer) throw new InvalidOperationException("config2-size");
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)needed));
        try
        {
            uint actual = 0;
            if (!QueryServiceConfig2(service, level, buffer, needed, out actual)
                    || actual == 0 || actual > needed)
                Fail("QueryServiceConfig2");
            bufferSize = actual;
            return buffer;
        }
        catch
        {
            Marshal.FreeHGlobal(buffer);
            throw;
        }
    }

    public static AmneziaServiceSnapshotNative Read(string serviceName)
    {
        if (String.IsNullOrEmpty(serviceName) || serviceName.Length > 256)
            throw new InvalidOperationException("service-name");
        IntPtr manager = IntPtr.Zero;
        IntPtr service = IntPtr.Zero;
        IntPtr config = IntPtr.Zero;
        IntPtr delayed = IntPtr.Zero;
        IntPtr failure = IntPtr.Zero;
        IntPtr flag = IntPtr.Zero;
        try
        {
            manager = OpenScManager(null, null, ScManagerConnect);
            if (manager == IntPtr.Zero) Fail("OpenSCManager");
            service = OpenService(manager, serviceName, ServiceQueryConfig);
            if (service == IntPtr.Zero) Fail("OpenService");
            uint configNeeded = 0;
            QueryServiceConfig(service, IntPtr.Zero, 0, out configNeeded);
            if (configNeeded == 0 || configNeeded > MaxBuffer) throw new InvalidOperationException("config-size");
            config = Marshal.AllocHGlobal(checked((int)configNeeded));
            uint configActual = 0;
            if (!QueryServiceConfig(service, config, configNeeded, out configActual)
                    || configActual == 0 || configActual > configNeeded)
                Fail("QueryServiceConfig");
            long begin = config.ToInt64();
            long end = checked(begin + configActual);
            int configSize = Marshal.SizeOf(typeof(QueryServiceConfigNative));
            if (!InRange(config, begin, end, configSize)) throw new InvalidOperationException("config-bounds");
            QueryServiceConfigNative configRecord = (QueryServiceConfigNative)Marshal.PtrToStructure(
                config, typeof(QueryServiceConfigNative));
            IntPtr image = PointerAt(config, FieldOffset(typeof(QueryServiceConfigNative), "imagePath"), begin, end);
            IntPtr dependencies = PointerAt(config, FieldOffset(typeof(QueryServiceConfigNative), "dependencies"), begin, end);
            IntPtr startName = PointerAt(config, FieldOffset(typeof(QueryServiceConfigNative), "startName"), begin, end);

            uint delayedSize = 0;
            delayed = QueryBuffer(service, QueryServiceConfig2DelayedAutoStart, out delayedSize);
            long delayedBegin = delayed.ToInt64();
            long delayedEnd = checked(delayedBegin + delayedSize);
            if (!InRange(delayed, delayedBegin, delayedEnd, 4)) throw new InvalidOperationException("delayed-bounds");
            int delayedValue = Marshal.ReadInt32(delayed);
            if (delayedValue != 0 && delayedValue != 1) throw new InvalidOperationException("delayed-value");

            uint failureSize = 0;
            failure = QueryBuffer(service, QueryServiceConfig2FailureActions, out failureSize);
            long failureBegin = failure.ToInt64();
            long failureEnd = checked(failureBegin + failureSize);
            int failureStructSize = Marshal.SizeOf(typeof(FailureActionsNative));
            if (!InRange(failure, failureBegin, failureEnd, failureStructSize)) throw new InvalidOperationException("failure-bounds");
            FailureActionsNative failureRecord = (FailureActionsNative)Marshal.PtrToStructure(
                failure, typeof(FailureActionsNative));
            IntPtr reboot = PointerAt(failure, FieldOffset(typeof(FailureActionsNative), "rebootMessage"), failureBegin, failureEnd);
            IntPtr command = PointerAt(failure, FieldOffset(typeof(FailureActionsNative), "commandLine"), failureBegin, failureEnd);
            IntPtr actions = PointerAt(failure, FieldOffset(typeof(FailureActionsNative), "actions"), failureBegin, failureEnd);
            if (failureRecord.actionCount > MaxDependencies
                    || (failureRecord.actionCount > 0 && actions == IntPtr.Zero))
                throw new InvalidOperationException("failure-shape");
            StringBuilder actionTypes = new StringBuilder();
            StringBuilder actionDelays = new StringBuilder();
            for (int i = 0; i < failureRecord.actionCount; ++i)
            {
                IntPtr action = new IntPtr(checked(actions.ToInt64() + (long)i * Marshal.SizeOf(typeof(ScActionNative))));
                if (!InRange(action, failureBegin, failureEnd, Marshal.SizeOf(typeof(ScActionNative)))) throw new InvalidOperationException("action-bounds");
                ScActionNative actionRecord = (ScActionNative)Marshal.PtrToStructure(
                    action, typeof(ScActionNative));
                if (i > 0) { actionTypes.Append('/'); actionDelays.Append('/'); }
                actionTypes.Append(actionRecord.type);
                actionDelays.Append(actionRecord.delay);
            }
            string rebootText = ReadString(reboot, failureBegin, failureEnd, true);
            string commandText = ReadString(command, failureBegin, failureEnd, true);

            uint flagSize = 0;
            flag = QueryBuffer(service, QueryServiceConfig2FailureActionsFlag, out flagSize);
            long flagBegin = flag.ToInt64();
            long flagEnd = checked(flagBegin + flagSize);
            if (!InRange(flag, flagBegin, flagEnd, 4)) throw new InvalidOperationException("flag-bounds");
            int flagValue = Marshal.ReadInt32(flag);
            if (flagValue != 0 && flagValue != 1) throw new InvalidOperationException("flag-value");

            return new AmneziaServiceSnapshotNative {
                name = serviceName,
                serviceType = checked((int)configRecord.serviceType),
                start = checked((int)configRecord.start),
                errorControl = checked((int)configRecord.errorControl),
                imagePath = ReadString(configRecord.imagePath, begin, end, false),
                dependencies = ReadMultiSz(dependencies, begin, end),
                startName = ReadString(configRecord.startName, begin, end, false),
                delayedAutoStart = delayedValue,
                failureActions = failureRecord.actionCount == 3 && actionTypes.ToString() == "1/1/1"
                        && actionDelays.ToString() == "2000/2000/2000" && failureRecord.resetPeriod == 100
                        && rebootText.Length == 0 && commandText.Length == 0
                    ? "restart/2000/restart/2000/restart/2000" : "",
                failureResetPeriod = failureRecord.resetPeriod,
                failureActionCount = checked((int)failureRecord.actionCount),
                failureActionTypes = actionTypes.ToString(),
                failureActionDelays = actionDelays.ToString(),
                rebootMessage = rebootText,
                commandLine = commandText,
                failureActionsFlag = flagValue,
                failureActionsFlagRaw = flagValue == 1 ? "TRUE" : "FALSE"
            };
        }
        finally
        {
            if (flag != IntPtr.Zero) Marshal.FreeHGlobal(flag);
            if (failure != IntPtr.Zero) Marshal.FreeHGlobal(failure);
            if (delayed != IntPtr.Zero) Marshal.FreeHGlobal(delayed);
            if (config != IntPtr.Zero) Marshal.FreeHGlobal(config);
            if (service != IntPtr.Zero) CloseServiceHandle(service);
            if (manager != IntPtr.Zero) CloseServiceHandle(manager);
        }
    }
}
