#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void wire_keygen(int64_t port_,
                 const unsigned char *secrets_byte_vec,
                 uintptr_t secrets_byte_len,
                 const unsigned char *group_byte_vec,
                 uintptr_t group_byte_len);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
