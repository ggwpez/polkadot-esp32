#ifdef NDEBUG
#error "QEMU door-policy assertions must be enabled"
#endif
#define main qemu_door_tests
#include "../test_door.c"
