#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void wire_keygen(int64_t port_,
                 wire_uint_8_list *secrets_byte_vec,
                 wire_uint_8_list *group_byte_vec);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
