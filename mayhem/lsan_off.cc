// Leak detection is not the bug class fuzzed here; ASan + UBSan stay fully on.
#ifdef __cplusplus
extern "C"
#endif
int __lsan_is_turned_off(void) { return 1; }
