// Test-only typed process boundary for the actual product main.
//
// Included inside bootstrap_n.cpp's anonymous namespace only when compiled
// with -DAMNEZIA_BOOTSTRAP_TEST_BOUNDARY.  It maps the fixed logical dpkg
// argv from the actual RuntimeContract onto an owned pure worker and appends
// every attempted invocation to an owned log.  It is not part of the product
// binary and does not add any product authentication.
ProbeResult test_probe_boundary(const std::vector<std::string> &argv,
                                const WorkDeadline &deadline) {
  const char *worker = ::getenv("AMNEZIA_TEST_WORKER");
  if (worker == nullptr || worker[0] != '/') {
    refuse(27, "test boundary requires an absolute owned worker");
  }
  const char *log_path = ::getenv("AMNEZIA_TEST_BOUNDARY_LOG");
  if (log_path != nullptr && *log_path != '\0') {
    std::string row;
    for (size_t i = 0; i < argv.size(); ++i) {
      if (i != 0) row += "\t";
      row += argv[i];
    }
    row += "\n";
    const int fd = ::open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) refuse(27, "test boundary log cannot be opened");
    write_all(fd, row);
    ::close(fd);
  }
  std::vector<std::string> mapped;
  mapped.push_back(worker);
  if (argv.size() == 4 && argv[0] == "/usr/bin/dpkg-query" && argv[1] == "-W") {
    mapped.push_back("query");
    mapped.push_back(argv[3]);
  } else if (argv.size() == 5 && argv[0] == "/usr/bin/dpkg" &&
             argv[1] == "--compare-versions") {
    mapped.push_back("compare");
    mapped.push_back(argv[2]);
    mapped.push_back("ge");
    mapped.push_back(argv[4]);
  } else if (argv.size() == 2 && argv[0] == "/usr/bin/dpkg" &&
             argv[1] == "--print-architecture") {
    mapped.push_back("arch");
  } else {
    refuse(27, "test boundary saw an unexpected logical program");
  }
  return run_probe_bounded(mapped, deadline);
}
