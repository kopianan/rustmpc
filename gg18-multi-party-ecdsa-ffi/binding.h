#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct WireSyncReturnStruct {
  uint8_t *ptr;
  int32_t len;
  bool success;
} WireSyncReturnStruct;

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int32_t error_message_utf8(char *buf, int32_t length);

void free_WireSyncReturnStruct(WireSyncReturnStruct val);

void getSignalServerCert(int64_t port);

int32_t last_error_length(void);

wire_uint_8_list *new_uint_8_list(int32_t len);

void store_dart_post_cobject(DartPostCObjectFnType ptr);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
