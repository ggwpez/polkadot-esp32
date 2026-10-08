/* Reuse the host suite against the firmware crypto implementation. */
#define LC_EMBED_FIXTURES
#define LC_FIXTURE_HEADER "fixtures/devnet/fixtures.h"
#define main qemu_core_tests
#include "../test_core.c"
