#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void http_local_run(int64_t port_);

void wire_keygen(int64_t port_, uint16_t index);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
