using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class OwnedOperatorResult {
 public int ProcessId, ExitCode;
 public bool Started, ExitCodeAvailable, TimedOut, OutputLimitExceeded, DrainCompleted, OwnedChildExited;
 public string Stdout = "", Stderr = "", Failure = "";
 public long ElapsedMilliseconds;
}
public static class BoundedOwnedOperator {
 static async Task<string> ReadBounded(StreamReader reader, int limit, Action overflow) {
  var text = new StringBuilder(); var buffer = new char[4096]; int n;
  while ((n = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) != 0) {
   int keep = Math.Min(n, limit - text.Length);
   if (keep > 0) text.Append(buffer, 0, keep);
   if (keep != n) { overflow(); break; }
  }
  return text.ToString();
 }
 public static OwnedOperatorResult Run(string executable, string arguments, int timeoutMs, int maxChars) {
  if (timeoutMs < 1 || timeoutMs > 18000 || maxChars < 1 || maxChars > 65536) throw new ArgumentOutOfRangeException();
  var result = new OwnedOperatorResult(); var timer = Stopwatch.StartNew(); int exceeded = 0;
  using (var process = new Process()) {
   process.StartInfo = new ProcessStartInfo(executable, arguments) {
    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
    RedirectStandardError = true, StandardOutputEncoding = new UTF8Encoding(false, true),
    StandardErrorEncoding = new UTF8Encoding(false, true), WorkingDirectory = Path.GetDirectoryName(executable)
   };
   Task<string> stdout = null, stderr = null;
   try {
    if (!process.Start()) throw new IOException("owned operator did not start");
    result.Started = true; result.ProcessId = process.Id;
    IntPtr ownedHandle = process.Handle; // Hold the exact child handle across wait/cleanup.
    Action overflow = () => { Interlocked.Exchange(ref exceeded, 1); try { if (!process.HasExited) process.Kill(); } catch { } };
    stdout = ReadBounded(process.StandardOutput, maxChars, overflow);
    stderr = ReadBounded(process.StandardError, maxChars, overflow);
    if (!process.WaitForExit(timeoutMs)) {
     result.TimedOut = true;
     if (!process.HasExited) process.Kill();
     process.WaitForExit(500);
    }
    result.OwnedChildExited = process.HasExited;
    if (result.OwnedChildExited) { result.ExitCode = process.ExitCode; result.ExitCodeAvailable = true; }
    result.DrainCompleted = Task.WaitAll(new Task[] { stdout, stderr }, 500);
    if (stdout.Status == TaskStatus.RanToCompletion) result.Stdout = stdout.Result;
    if (stderr.Status == TaskStatus.RanToCompletion) result.Stderr = stderr.Result;
   } catch (Exception error) {
    result.Failure = error.GetType().FullName + ": " + error.Message;
   } finally {
    // No process-tree/name kill: only the handle of this invocation's child.
    if (result.Started) {
     try { if (!process.HasExited) { process.Kill(); process.WaitForExit(500); } result.OwnedChildExited = process.HasExited; }
     catch (Exception error) { result.Failure += "; cleanup=" + error.GetType().FullName; }
     if (result.OwnedChildExited && !result.ExitCodeAvailable) {
      try { result.ExitCode = process.ExitCode; result.ExitCodeAvailable = true; } catch { }
     }
    } else result.OwnedChildExited = true;
    try { if (stdout != null) process.StandardOutput.Close(); } catch { }
    try { if (stderr != null) process.StandardError.Close(); } catch { }
   }
  }
  result.OutputLimitExceeded = Volatile.Read(ref exceeded) != 0;
  result.ElapsedMilliseconds = timer.ElapsedMilliseconds;
  return result;
 }
}
