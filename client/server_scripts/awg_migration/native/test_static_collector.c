/* Distinct static native collector fixture; never a product executable. */
static const char collector_fixture_marker[] = "native-log-collector-fixture";
int main(void) { return collector_fixture_marker[0] == 'n' ? 0 : 1; }
