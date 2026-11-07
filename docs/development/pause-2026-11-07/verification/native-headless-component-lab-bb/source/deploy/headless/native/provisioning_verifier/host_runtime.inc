// Proposal N: bounded host runtime probe workflow.
//
// This file is included by bootstrap_n.cpp at the exact point where K's
// unbounded ProbeResult/run_probe/resolve_path_command/run_probe_host block
// lived.  It keeps K's product modes and all preceding authentication code
// byte-identical.
//
// Contract source: deploy/headless/install_headless.sh Python block 930-977
// (read in full) and the linked native validator
// require_runtime_contract() already present in preauth_modes.cpp.

struct ProbeResult {
  int exit_code = 127;
  bool signaled = false;
  bool truncated = false;
  bool timed_out = false;
  std::string output;
  std::string stderr_output;
};

struct WorkDeadline {
  using Clock = std::chrono::steady_clock;
  Clock::time_point work_end;
  Clock::time_point cleanup_end;

  static WorkDeadline from_now(std::chrono::milliseconds work,
                               std::chrono::milliseconds cleanup) {
    const Clock::time_point now = Clock::now();
    WorkDeadline deadline;
    deadline.work_end = now + work;
    deadline.cleanup_end = deadline.work_end + cleanup;
    return deadline;
  }
  static WorkDeadline standard() {
    return from_now(std::chrono::milliseconds(30000),
                    std::chrono::milliseconds(1500));
  }
  int work_remaining_ms() const {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
        work_end - Clock::now()).count();
    if (left <= 0) return 0;
    return left > 2000000000 ? 2000000000 : static_cast<int>(left);
  }
  int cleanup_remaining_ms() const {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
        cleanup_end - Clock::now()).count();
    if (left <= 0) return 0;
    return left > 2000000000 ? 2000000000 : static_cast<int>(left);
  }
};

// One bounded probe.  The caller supplies the single absolute work deadline
// for the whole host workflow; this function never resets or extends it.
// stdout and stderr are separate pipes.  A nonempty stderr, overflow, signal,
// timeout or unreapable child is a closed refusal, not probe data.
ProbeResult run_probe_bounded(const std::vector<std::string> &argv,
                              const WorkDeadline &deadline) {
  if (argv.empty() || argv[0].empty() || argv[0][0] != '/') {
    refuse(20, "probe argv must start with an absolute executable path");
  }
  int out_fds[2] = {-1, -1};
  int err_fds[2] = {-1, -1};
  if (::pipe2(out_fds, O_CLOEXEC) != 0 || ::pipe2(err_fds, O_CLOEXEC) != 0) {
    if (out_fds[0] >= 0) { ::close(out_fds[0]); ::close(out_fds[1]); }
    if (err_fds[0] >= 0) { ::close(err_fds[0]); ::close(err_fds[1]); }
    refuse(21, "probe pipe creation failed");
  }
  const pid_t child = ::fork();
  if (child < 0) {
    ::close(out_fds[0]); ::close(out_fds[1]);
    ::close(err_fds[0]); ::close(err_fds[1]);
    refuse(21, "probe fork failed");
  }
  if (child == 0) {
    ::setpgid(0, 0);
    ::close(out_fds[0]);
    ::close(err_fds[0]);
    if (::dup2(out_fds[1], STDOUT_FILENO) < 0 ||
        ::dup2(err_fds[1], STDERR_FILENO) < 0) {
      ::_exit(126);
    }
    ::close(out_fds[1]);
    ::close(err_fds[1]);
    std::vector<char *> raw;
    raw.reserve(argv.size() + 1);
    for (const auto &item : argv) raw.push_back(const_cast<char *>(item.c_str()));
    raw.push_back(nullptr);
    ::execv(raw[0], raw.data());
    ::_exit(127);
  }
  (void)::setpgid(child, child);
  ::close(out_fds[1]);
  ::close(err_fds[1]);

  ProbeResult result;
  bool timed_out = false;
  bool out_open = true;
  bool err_open = true;
  char buffer[8192];
  auto consume = [&](int fd, std::string &sink, bool &open) -> bool {
    const ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count == 0) {
      ::close(fd);
      open = false;
      return true;
    }
    if (count < 0) {
      if (errno == EINTR) return true;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
      return false;
    }
    const size_t size = static_cast<size_t>(count);
    if (sink.size() + size > kMaxProbeOutputBytes) {
      const size_t room = kMaxProbeOutputBytes - sink.size();
      sink.append(buffer, room);
      result.truncated = true;
    } else {
      sink.append(buffer, size);
    }
    return true;
  };
  auto terminate_child = [&]() {
    ::kill(-child, SIGKILL);
    ::kill(child, SIGKILL);
    while (true) {
      const pid_t waited = ::waitpid(child, nullptr, WNOHANG);
      if (waited == child || (waited < 0 && errno == ECHILD)) return;
      if (waited < 0 && errno != EINTR) return;
      if (deadline.cleanup_remaining_ms() <= 0) return;
      ::poll(nullptr, 0, 10);
    }
  };
  while (out_open || err_open) {
    const int remaining = deadline.work_remaining_ms();
    if (remaining <= 0) {
      timed_out = true;
      break;
    }
    struct pollfd fds[2];
    nfds_t count = 0;
    if (out_open) fds[count++] = {out_fds[0], POLLIN, 0};
    if (err_open) fds[count++] = {err_fds[0], POLLIN, 0};
    const int ready = ::poll(fds, count, remaining);
    if (ready < 0) {
      if (errno == EINTR) continue;
      terminate_child();
      if (out_open) ::close(out_fds[0]);
      if (err_open) ::close(err_fds[0]);
      refuse(27, "probe poll failed");
    }
    if (ready == 0) {
      timed_out = true;
      break;
    }
    for (nfds_t index = 0; index < count; ++index) {
      if ((fds[index].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
      const int fd = fds[index].fd;
      if (fd == out_fds[0] && out_open) {
        if (!consume(fd, result.output, out_open)) {
          terminate_child();
          if (out_open) ::close(out_fds[0]);
          if (err_open) ::close(err_fds[0]);
          refuse(27, "probe stdout read failed");
        }
      } else if (fd == err_fds[0] && err_open) {
        if (!consume(fd, result.stderr_output, err_open)) {
          terminate_child();
          if (out_open) ::close(out_fds[0]);
          if (err_open) ::close(err_fds[0]);
          refuse(27, "probe stderr read failed");
        }
      }
    }
  }

  bool reaped = false;
  bool status_known = false;
  int status = 0;
  auto reap_once = [&]() -> bool {
    while (true) {
      const pid_t waited = ::waitpid(child, &status, WNOHANG);
      if (waited == child) { reaped = true; status_known = true; return true; }
      if (waited < 0 && errno == ECHILD) { reaped = true; return true; }
      if (waited < 0 && errno != EINTR) return false;
      if (waited == 0) return false;
    }
  };
  if (timed_out) {
    ::kill(-child, SIGKILL);
    ::kill(child, SIGKILL);
  }
  while (!reap_once()) {
    if (deadline.work_remaining_ms() <= 0 && !timed_out) {
      timed_out = true;
      ::kill(-child, SIGKILL);
      ::kill(child, SIGKILL);
    }
    if (deadline.cleanup_remaining_ms() <= 0) break;
    ::poll(nullptr, 0, 10);
  }
  if (out_open) ::close(out_fds[0]);
  if (err_open) ::close(err_fds[0]);

  result.timed_out = timed_out;
  if (!reaped) {
    refuse(27, "probe child could not be reaped within the cleanup bound");
  }
  if (timed_out) {
    refuse(27, "probe exceeded the single absolute work deadline");
  }
  if (!status_known) {
    refuse(27, "probe native exit status is unavailable");
  }
  if (result.truncated) {
    refuse(27, "probe output exceeded the 64 KiB bound");
  }
  if (!result.stderr_output.empty()) {
    refuse(27, "probe wrote to stderr; status contamination is not accepted");
  }
  if (WIFSIGNALED(status)) {
    result.signaled = true;
    result.exit_code = 128 + WTERMSIG(status);
    refuse(27, "probe terminated by a signal");
  }
  if (!WIFEXITED(status)) {
    refuse(27, "probe did not exit normally");
  }
  result.exit_code = WEXITSTATUS(status);
  return result;
}

// Program whitelist: the host workflow may only execute these absolute,
// OS-trusted dpkg programs.  PATH is used to validate command existence, not
// to select an executable and never from CWD/relative or empty elements.
bool trusted_probe_program(const std::string &path) {
  return path == "/usr/bin/dpkg-query" || path == "/usr/bin/dpkg";
}

bool path_program_exists(const std::string &name) {
  if (name.empty() || name.find('/') != std::string::npos) return false;
  const char *path = ::getenv("PATH");
  if (path == nullptr || *path == '\0') return false;
  const std::string value(path);
  size_t start = 0;
  while (start <= value.size()) {
    const size_t end = value.find(':', start);
    const std::string element =
        end == std::string::npos ? value.substr(start) : value.substr(start, end - start);
    // Empty or relative PATH elements would inject the process CWD.
    if (!element.empty() && element[0] == '/') {
      const std::string candidate = element + "/" + name;
      struct stat metadata {};
      if (::stat(candidate.c_str(), &metadata) == 0 &&
          S_ISREG(metadata.st_mode) && ::access(candidate.c_str(), X_OK) == 0) {
        return true;
      }
    }
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return false;
}

std::string trim_text(std::string value) {
  while (!value.empty() && (value.back() == '\n' || value.back() == '\r' ||
                            value.back() == ' ' || value.back() == '\t')) {
    value.pop_back();
  }
  size_t start = 0;
  while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
    ++start;
  }
  return value.substr(start);
}

#ifdef AMNEZIA_BOOTSTRAP_TEST_BOUNDARY
#include "../tests/test_boundary.inc"
#endif

ProbeResult probe_transport(const std::vector<std::string> &argv,
                            const WorkDeadline &deadline) {
#ifdef AMNEZIA_BOOTSTRAP_TEST_BOUNDARY
  return test_probe_boundary(argv, deadline);
#else
  return run_probe_bounded(argv, deadline);
#endif
}

// Actual host workflow.  Pre-validation (arguments, file read, JSON parse and
// the full RuntimeContract) completes before the first process boundary.
// Backend availability is the canonical ANY declared mode, required commands
// are all mandatory, packages accept the first satisfied alternative, and
// architecture must be exactly amd64.  Runtime success is hostProbesPassed;
// releaseAccepted is always false.
int run_probe_host(int argc, char **argv) {
  static const std::vector<std::string> allowed = {
      "--runtime-manifest", "--ubuntu-version-id", "--ubuntu-codename"};
  const auto args = parse_mode_arguments(argc, argv, allowed, "");
  const std::string manifest_path = required_argument(args, "--runtime-manifest", "");
  const std::string version_id = required_argument(args, "--ubuntu-version-id", "");
  const std::string codename = required_argument(args, "--ubuntu-codename", "");
  const FileBytes manifest_bytes = read_regular_bytes(
      manifest_path, kMaxJournalBytes, "runtime dependency manifest");

  Json runtime;
  try {
    runtime = parse_json(manifest_bytes.bytes);
  } catch (const std::exception &error) {
    refuse(22, std::string("runtime dependency manifest is not valid JSON: ") +
                   error.what());
  }
  RuntimeContract contract;
  try {
    contract = require_runtime_contract(runtime, "ubuntu", version_id, codename);
  } catch (const std::exception &error) {
    refuse(22, std::string("runtime dependency manifest contract refused: ") +
                   error.what());
  }

  const WorkDeadline deadline = WorkDeadline::standard();
  std::string out = "{\"schema\":1,\"tool\":\"amnezia-headless-host-probe-v1\",";
  out += "\"hostProbesExecuted\":false,";
  out += "\"requiredCommands\":[";
  bool all_ok = true;
  bool first = true;
  for (const std::string &name : contract.required_commands) {
    const bool found = path_program_exists(name);
    all_ok = all_ok && found;
    if (!first) out += ",";
    first = false;
    out += "{\"name\":" + quote_json(name) + ",\"present\":" +
           (found ? "true" : "false") + "}";
  }
  out += "],\"backendModes\":[";
  bool any_mode = false;
  first = true;
  for (const auto &mode : contract.backend_modes) {
    bool satisfied = false;
    for (const auto &alternative : mode.second) {
      if (path_program_exists(alternative)) satisfied = true;
    }
    any_mode = any_mode || satisfied;
    if (!first) out += ",";
    first = false;
    out += "{\"mode\":" + quote_json(mode.first) + ",\"satisfied\":" +
           (satisfied ? "true" : "false") + "}";
  }
  all_ok = all_ok && any_mode;
  out += "],\"packages\":[";

  // Canonical Python raises on the first missing required command or missing
  // backend mode, before any package/architecture subprocess.  Preserve that
  // order: no OS process boundary on a failed preflight.
  if (!all_ok) {
    out += "],\"architecture\":\"not-probed\",\"hostProbesPassed\":false,";
    out += "\"releaseAccepted\":false}\n";
    std::fputs(out.c_str(), stdout);
    return 26;
  }

  out.replace(out.find("\"hostProbesExecuted\":false"),
               std::string("\"hostProbesExecuted\":false").size(),
               "\"hostProbesExecuted\":true");
  const std::string installed_prefix = "install ok installed\t";
  auto trusted_probe = [&](const std::vector<std::string> &command) {
    if (!trusted_probe_program(command.front())) {
      refuse(27, "host workflow attempted an untrusted program");
    }
    return probe_transport(command, deadline);
  };

  first = true;
  for (const auto &package : contract.packages) {
    bool satisfied = false;
    for (const auto &alternative : package.first) {
      const ProbeResult query = trusted_probe(
          {"/usr/bin/dpkg-query", "-W", "-f=${Status}\t${Version}", alternative});
      if (query.exit_code != 0 ||
          query.output.compare(0, installed_prefix.size(), installed_prefix) != 0) {
        continue;
      }
      const std::string rest = query.output.substr(installed_prefix.size());
      const size_t newline = rest.find('\n');
      const std::string installed =
          trim_text(rest.substr(0, newline == std::string::npos ? std::string::npos
                                                               : newline));
      if (installed.empty()) continue;
      const ProbeResult compare = trusted_probe(
          {"/usr/bin/dpkg", "--compare-versions", installed, "ge", package.second});
      if (compare.exit_code == 0) {
        satisfied = true;
        break;
      }
    }
    all_ok = all_ok && satisfied;
    if (!first) out += ",";
    first = false;
    out += "{\"minimum\":" + quote_json(package.second) + ",\"satisfied\":" +
           (satisfied ? "true" : "false") + "}";
  }
  out += "],\"architecture\":";
  const ProbeResult architecture = trusted_probe({"/usr/bin/dpkg", "--print-architecture"});
  const bool arch_ok = architecture.exit_code == 0 &&
                       trim_text(architecture.output) == "amd64";
  all_ok = all_ok && arch_ok;
  out += arch_ok ? "\"amd64\"" : "\"unexpected\"";
  out += ",\"hostProbesPassed\":" + std::string(all_ok ? "true" : "false");
  out += ",\"releaseAccepted\":false}\n";
  std::fputs(out.c_str(), stdout);
  return all_ok ? 0 : 26;
}
